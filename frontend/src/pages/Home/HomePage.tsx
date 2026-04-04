import { useNavigate } from 'react-router-dom';
import { Row, Col } from '@govtechsg/sgds-react';
import { FileList } from '@components/upload/FileList';

export const HomePage = () => {
  const navigate = useNavigate();

  return (
    <div className="home-page">
      <Row className="justify-content-center">
        <Col lg={10}>
          <div className="text-center mb-4">
            <h2 className="mb-2">TracePcap</h2>
            <p className="text-muted mb-3">PCAP File Analysis &amp; Network Traffic Storytelling</p>
            <button className="btn btn-primary" onClick={() => navigate('/upload')}>
              <i className="bi bi-upload me-2"></i>
              Upload PCAP
            </button>
          </div>

          <FileList />
        </Col>
      </Row>
    </div>
  );
};
