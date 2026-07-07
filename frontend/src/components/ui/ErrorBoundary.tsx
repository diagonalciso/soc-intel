import React from 'react'

interface State { error: Error | null }

export class ErrorBoundary extends React.Component<{ children: React.ReactNode }, State> {
  state: State = { error: null }

  static getDerivedStateFromError(error: Error): State {
    return { error }
  }

  render() {
    if (this.state.error) {
      return (
        <div style={{ padding: 40, color: '#f85149', fontFamily: 'monospace', fontSize: 13 }}>
          <div style={{ fontSize: 16, marginBottom: 12 }}>Something went wrong</div>
          <pre style={{ whiteSpace: 'pre-wrap', color: '#8b949e' }}>
            {this.state.error.message}
          </pre>
          <button
            onClick={() => this.setState({ error: null })}
            style={{ marginTop: 16, padding: '6px 14px', background: '#1c2128', border: '1px solid #30363d', color: '#e6edf3', borderRadius: 4, cursor: 'pointer' }}
          >
            Retry
          </button>
        </div>
      )
    }
    return this.props.children
  }
}
