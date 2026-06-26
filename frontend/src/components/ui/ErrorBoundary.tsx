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
        <div style={{ padding: 40, color: '#ef4444', fontFamily: 'monospace', fontSize: 13 }}>
          <div style={{ fontSize: 16, marginBottom: 12 }}>Something went wrong</div>
          <pre style={{ whiteSpace: 'pre-wrap', color: '#94a3b8' }}>
            {this.state.error.message}
          </pre>
          <button
            onClick={() => this.setState({ error: null })}
            style={{ marginTop: 16, padding: '6px 14px', background: '#1e2533', border: '1px solid #2d3748', color: '#e2e8f0', borderRadius: 4, cursor: 'pointer' }}
          >
            Retry
          </button>
        </div>
      )
    }
    return this.props.children
  }
}
