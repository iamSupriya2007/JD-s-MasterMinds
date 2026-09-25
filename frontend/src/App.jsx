import { useEffect, useState } from 'react'
import './App.css'

const API_URL = import.meta.env.DEV ? '/api/dashboard' : 'http://localhost:8080/api/dashboard'
const severityOrder = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']

const normalizeSeverity = (value) => {
  const safeValue = String(value ?? 'LOW').trim().toUpperCase()
  return severityOrder.includes(safeValue) ? safeValue : 'LOW'
}

const formatTimestamp = (value) => {
  if (!value) return '—'

  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return value

  return new Intl.DateTimeFormat('en-US', {
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  }).format(date)
}

const truncateText = (value, maxLength = 64) => {
  if (!value) return '—'
  if (value.length <= maxLength) return value
  return `${value.slice(0, maxLength - 1)}…`
}

const formatFileSummary = (files = []) => {
  if (!files || files.length === 0) return '—'
  if (files.length === 1) return truncateText(files[0], 48)

  const names = files.slice(0, 2).map((file) => truncateText(file, 36)).join(', ')
  return `${names} +${files.length - 2} more`
}

function App() {
  const [dashboard, setDashboard] = useState(null)
  const [loading, setLoading] = useState(true)
  const [refreshing, setRefreshing] = useState(false)
  const [error, setError] = useState('')
  const [statusMessage, setStatusMessage] = useState('')
  const [lastUpdated, setLastUpdated] = useState(null)
  const [selectedIncidentId, setSelectedIncidentId] = useState(null)

  const fetchDashboard = async (silent = false) => {
    try {
      if (!silent) {
        setError('')
      }
      setRefreshing(true)

      const response = await fetch(API_URL)
      if (!response.ok) {
        throw new Error(`Request failed with status ${response.status}`)
      }

      const data = await response.json()
      setDashboard(data)
      setLastUpdated(new Date().toISOString())
      setStatusMessage('Live data refreshed')
      setError('')
    } catch (fetchError) {
      const message =
        fetchError instanceof Error
          ? `Refresh failed: ${fetchError.message}`
          : 'Refresh failed. Showing the last valid dashboard data.'

      setStatusMessage(message)
      setError(message)
      if (!dashboard) {
        setDashboard(null)
      }
    } finally {
      setLoading(false)
      setRefreshing(false)
    }
  }

  useEffect(() => {
    fetchDashboard(false)
  }, [])

  useEffect(() => {
    const intervalId = window.setInterval(() => {
      fetchDashboard(true)
    }, 5000)

    return () => {
      window.clearInterval(intervalId)
    }
  }, [dashboard])

  useEffect(() => {
    if (!selectedIncidentId) {
      return
    }

    const incidentExists = (dashboard?.recentIncidents ?? []).some(
      (incident) => incident.incidentId === selectedIncidentId,
    )

    if (!incidentExists) {
      setSelectedIncidentId(null)
    }
  }, [dashboard, selectedIncidentId])

  const summary = dashboard?.summary ?? {}
  const systemStatus = dashboard?.systemStatus ?? {}
  const recentActivity = dashboard?.recentActivity ?? []
  const recentIncidents = dashboard?.recentIncidents ?? []
  const severityCounts = summary.severityCounts ?? {}

  const summaryCards = [
    { label: 'Audit Events', value: summary.totalAuditEvents ?? 0 },
    { label: 'Incidents', value: summary.totalIncidents ?? 0 },
    { label: 'Low', value: severityCounts.LOW ?? 0 },
    { label: 'Medium', value: severityCounts.MEDIUM ?? 0 },
    { label: 'High', value: severityCounts.HIGH ?? 0 },
    { label: 'Critical', value: severityCounts.CRITICAL ?? 0 },
  ]

  const monitoringStatus = systemStatus.monitoringStatus ?? 'UNKNOWN'
  const auditStatus = systemStatus.auditChainVerificationStatus ?? 'UNKNOWN'

  const selectedIncident = recentIncidents.find(
    (incident) => incident.incidentId === selectedIncidentId,
  )

  const incidentTimeline = [...recentActivity]
    .filter((event) => event.incidentId === selectedIncidentId)
    .sort((a, b) => a.sequenceNumber - b.sequenceNumber)

  const uniqueEventTypes = [...new Set(incidentTimeline.map((event) => event.eventType).filter(Boolean))]
  const incidentFileCount = selectedIncident?.affectedFiles?.length ?? 0
  const primaryEvent = incidentTimeline[0]?.eventType ?? 'file-system activity'
  const storySummary = (() => {
    if (!selectedIncident) {
      return 'No incident selected.'
    }

    const eventCount = incidentTimeline.length || selectedIncident.eventCount || 0
    const fileCount = incidentFileCount
    const eventSummary = uniqueEventTypes.length > 0 ? uniqueEventTypes.join(', ') : 'file-system events'

    if (eventCount <= 1) {
      return `${eventCount} file-system event was detected within the incident window. The activity involved ${fileCount} affected file(s) and included ${primaryEvent.toLowerCase()} activity.`
    }

    return `${eventCount} file-system events were detected within the incident window. The activity involved ${fileCount} affected file(s) and included ${eventSummary.toLowerCase()} events.`
  })()

  return (
    <div className="dashboard-shell">
      <header className="topbar panel">
        <div className="brand-block">
          <div className="brand-line">
            <span className="brand-mark" aria-hidden="true" />
            <span className="brand-label">Security Monitor</span>
          </div>
          <p className="subtitle">File Integrity &amp; Incident Detection</p>
        </div>

        <div className="header-actions">
          <div className="status-stack">
            <div className={`status-pill ${monitoringStatus.toLowerCase()}`}>
              <span className="status-dot" />
              Monitoring: {monitoringStatus}
            </div>
            <div className={`status-pill ${auditStatus.toLowerCase()}`}>
              <span className="status-dot" />
              Audit Chain: {auditStatus}
            </div>
          </div>

          <button
            type="button"
            className="refresh-button"
            onClick={() => fetchDashboard()}
            disabled={loading || refreshing}
          >
            {refreshing ? 'Refreshing...' : 'Refresh'}
          </button>
        </div>
      </header>

      {lastUpdated ? (
        <div className="timestamp-row">
          <span>Last updated</span>
          <strong>{formatTimestamp(lastUpdated)}</strong>
        </div>
      ) : null}

      {statusMessage ? (
        <div className={`status-banner ${error ? 'status-banner-error' : 'status-banner-success'}`}>
          {statusMessage}
        </div>
      ) : null}

      {error && !dashboard ? (
        <div className="panel error-panel">
          <h2>Dashboard unavailable</h2>
          <p>{error}</p>
        </div>
      ) : null}

      {loading && !dashboard ? (
        <div className="panel loading-panel">
          <div className="loader" aria-label="Loading dashboard" />
          <p>Loading dashboard data...</p>
        </div>
      ) : null}

      {!loading && dashboard ? (
        <>
          <section className="summary-grid" aria-label="Summary metrics">
            {summaryCards.map((card) => (
              <article key={card.label} className="summary-card">
                <span className="card-label">{card.label}</span>
                <strong>{card.value}</strong>
              </article>
            ))}
          </section>

          <section className="panel">
            <div className="section-header">
              <h2>Recent Activity</h2>
            </div>

            <div className="table-wrap">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Seq</th>
                    <th>Time</th>
                    <th>Incident</th>
                    <th>Event</th>
                    <th>File</th>
                    <th>Severity</th>
                  </tr>
                </thead>
                <tbody>
                  {recentActivity.length > 0 ? (
                    recentActivity.map((activity) => (
                      <tr key={`${activity.sequenceNumber}-${activity.incidentId ?? 'activity'}`}>
                        <td className="mono">{activity.sequenceNumber}</td>
                        <td className="mono">{formatTimestamp(activity.timestamp)}</td>
                        <td className="mono">{activity.incidentId || '—'}</td>
                        <td className="mono">{activity.eventType || '—'}</td>
                        <td className="file-cell mono" title={activity.filePath || ''}>
                          {truncateText(activity.filePath, 60)}
                        </td>
                        <td>
                          <span className={`severity-badge severity-${normalizeSeverity(activity.severity).toLowerCase()}`}>
                            {normalizeSeverity(activity.severity)}
                          </span>
                        </td>
                      </tr>
                    ))
                  ) : (
                    <tr>
                      <td colSpan="6" className="empty-row">
                        No recent activity recorded.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </section>

          <section className="panel">
            <div className="section-header">
              <h2>Recent Incidents</h2>
            </div>

            <div className="table-wrap">
              <table className="data-table incident-table">
                <thead>
                  <tr>
                    <th>Incident</th>
                    <th>Start</th>
                    <th>Last Event</th>
                    <th>Events</th>
                    <th>Files</th>
                    <th>Severity</th>
                    <th>Reason</th>
                  </tr>
                </thead>
                <tbody>
                  {recentIncidents.length > 0 ? (
                    recentIncidents.map((incident) => (
                      <tr
                        key={incident.incidentId ?? `${incident.startTime}-${incident.lastEventTime}`}
                        className={selectedIncidentId === incident.incidentId ? 'selected-row' : ''}
                        onClick={() => setSelectedIncidentId(incident.incidentId)}
                        onKeyDown={(event) => {
                          if (event.key === 'Enter' || event.key === ' ') {
                            event.preventDefault()
                            setSelectedIncidentId(incident.incidentId)
                          }
                        }}
                        tabIndex={0}
                        role="button"
                      >
                        <td className="mono">{incident.incidentId || '—'}</td>
                        <td className="mono">{formatTimestamp(incident.startTime)}</td>
                        <td className="mono">{formatTimestamp(incident.lastEventTime)}</td>
                        <td className="mono">{incident.eventCount ?? 0}</td>
                        <td className="files-cell" title={incident.affectedFiles?.join(', ') ?? ''}>
                          <span className="file-count">{incident.affectedFiles?.length ?? 0}</span>
                          <span className="file-list">{formatFileSummary(incident.affectedFiles)}</span>
                        </td>
                        <td>
                          <span className={`severity-badge severity-${normalizeSeverity(incident.severity).toLowerCase()}`}>
                            {normalizeSeverity(incident.severity)}
                          </span>
                        </td>
                        <td className="reason-cell">{incident.severityReason || '—'}</td>
                      </tr>
                    ))
                  ) : (
                    <tr>
                      <td colSpan="7" className="empty-row">
                        No incidents available.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </section>

          {selectedIncident ? (
            <section className="panel incident-details-panel">
              <div className="details-header">
                <div>
                  <p className="details-label">Incident Details</p>
                  <h3>{selectedIncident.incidentId}</h3>
                </div>

                <button
                  type="button"
                  className="close-details-button"
                  onClick={() => setSelectedIncidentId(null)}
                >
                  Close details
                </button>
              </div>

              <div className="details-summary">
                <div className="details-summary-block">
                  <span className="meta-label">Severity</span>
                  <span className={`severity-badge severity-${normalizeSeverity(selectedIncident.severity).toLowerCase()}`}>
                    {normalizeSeverity(selectedIncident.severity)}
                  </span>
                </div>
                <div className="details-summary-block">
                  <span className="meta-label">Severity reason</span>
                  <strong>{selectedIncident.severityReason || '—'}</strong>
                </div>
                <div className="details-summary-block">
                  <span className="meta-label">Start time</span>
                  <strong className="mono">{formatTimestamp(selectedIncident.startTime)}</strong>
                </div>
                <div className="details-summary-block">
                  <span className="meta-label">Last event</span>
                  <strong className="mono">{formatTimestamp(selectedIncident.lastEventTime)}</strong>
                </div>
                <div className="details-summary-block">
                  <span className="meta-label">Event count</span>
                  <strong>{selectedIncident.eventCount ?? 0}</strong>
                </div>
                <div className="details-summary-block">
                  <span className="meta-label">Affected files</span>
                  <strong>{incidentFileCount}</strong>
                </div>
              </div>

              <div className="details-grid">
                <div className="details-panel-block">
                  <h4>Attack Story</h4>
                  <p>{storySummary}</p>
                </div>

                <div className="details-panel-block">
                  <h4>Affected File Paths</h4>
                  <ul className="file-list-stack">
                    {(selectedIncident.affectedFiles && selectedIncident.affectedFiles.length > 0)
                      ? selectedIncident.affectedFiles.map((file) => (
                          <li key={file} className="mono">{truncateText(file, 120)}</li>
                        ))
                      : <li>None recorded.</li>}
                  </ul>
                </div>
              </div>

              <div className="timeline-section">
                <h4>Incident Timeline</h4>

                <div className="table-wrap">
                  <table className="data-table timeline-table">
                    <thead>
                      <tr>
                        <th>Seq</th>
                        <th>Timestamp</th>
                        <th>Event Type</th>
                        <th>File Path</th>
                        <th>Severity</th>
                      </tr>
                    </thead>
                    <tbody>
                      {incidentTimeline.length > 0 ? (
                        incidentTimeline.map((event) => (
                          <tr key={`${event.sequenceNumber}-${event.incidentId ?? 'timeline'}`}>
                            <td className="mono">{event.sequenceNumber}</td>
                            <td className="mono">{formatTimestamp(event.timestamp)}</td>
                            <td className="mono">{event.eventType || '—'}</td>
                            <td className="file-cell mono" title={event.filePath || ''}>
                              {truncateText(event.filePath, 80)}
                            </td>
                            <td>
                              <span className={`severity-badge severity-${normalizeSeverity(event.severity).toLowerCase()}`}>
                                {normalizeSeverity(event.severity)}
                              </span>
                            </td>
                          </tr>
                        ))
                      ) : (
                        <tr>
                          <td colSpan="5" className="empty-row">
                            No timeline events available for this incident.
                          </td>
                        </tr>
                      )}
                    </tbody>
                  </table>
                </div>
              </div>
            </section>
          ) : null}
        </>
      ) : null}
    </div>
  )
}

export default App
