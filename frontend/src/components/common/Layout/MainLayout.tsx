import { Link, Outlet } from 'react-router-dom';
import { Container, Row, Col } from '@govtechsg/sgds-react';
import { Activity } from 'lucide-react';

export const MainLayout = () => {
  return (
    <div className="main-layout">
      <header className="main-header">
        <Container>
          <div className="d-flex align-items-center justify-content-between py-3">
            <Link to="/" style={{ textDecoration: 'none', color: 'inherit' }}>
              <div className="d-flex align-items-center gap-3">
                <Activity size={32} className="text-primary" />
                <div>
                  <h4 className="mb-0">TracePcap</h4>
                  <small className="text-muted">Network Analysis</small>
                </div>
              </div>
            </Link>
          </div>
        </Container>
      </header>
      <main className="main-content">
        <Outlet />
      </main>
      <footer className="main-footer mt-auto py-4 bg-light">
        <Container>
          <Row>
            <Col className="text-center text-muted">
              <small>TracePcap &copy; 2026 - Network Traffic Analysis and Visualization Tool</small>
            </Col>
          </Row>
        </Container>
      </footer>
    </div>
  );
};
