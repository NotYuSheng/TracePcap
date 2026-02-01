import { Link, Outlet } from 'react-router-dom'

export const MainLayout = () => {
  return (
    <div className="main-layout">
      <header className="main-header">
        <Link to="/" style={{ textDecoration: 'none', color: 'inherit' }}>
          <h2>TracePcap</h2>
        </Link>
      </header>
      <main className="main-content">
        <Outlet />
      </main>
      <footer className="main-footer">
        <p>&copy; 2026 TracePcap. PCAP Analysis Tool.</p>
      </footer>
    </div>
  )
}
