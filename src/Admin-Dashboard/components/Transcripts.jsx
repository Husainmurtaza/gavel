import React, { useEffect, useState } from 'react';
import Sidebar from './Sidebar';
import Dialog from '@mui/material/Dialog';
import DialogTitle from '@mui/material/DialogTitle';
import DialogContent from '@mui/material/DialogContent';
import DialogActions from '@mui/material/DialogActions';
import Button from '@mui/material/Button';
import Table from '@mui/material/Table';
import TableBody from '@mui/material/TableBody';
import TableCell from '@mui/material/TableCell';
import TableContainer from '@mui/material/TableContainer';
import TableHead from '@mui/material/TableHead';
import TableRow from '@mui/material/TableRow';
import Paper from '@mui/material/Paper';
import { authenticatedFetch } from '../../utils/api';

const getReviewStatusBadge = (status) => {
  const baseSx = {
    px: 1.5,
    py: 0.5,
    borderRadius: 2,
    fontSize: '0.9rem',
    fontWeight: 600,
    whiteSpace: 'nowrap',
    display: 'inline-block',
  };
  switch (status) {
    case 'pending':
      return <span style={{...baseSx, background: '#fef9c3', color: '#a16207'}}>Pending</span>;
    case 'approved':
      return <span style={{...baseSx, background: '#bbf7d0', color: '#166534'}}>Approved</span>;
    case 'rejected':
      return <span style={{...baseSx, background: '#fecaca', color: '#991b1b'}}>Rejected</span>;
    default:
      return <span style={{...baseSx, background: '#e5e7eb', color: '#374151'}}>{status}</span>;
  }
};

const AdminTranscripts = () => {
  const [interviews, setInterviews] = useState([]);
  const [loading, setLoading] = useState(true);
  const [modalOpen, setModalOpen] = useState(false);
  const [selectedInterview, setSelectedInterview] = useState(null);

  const fetchInterviews = async () => {
    setLoading(true);
    try {
      const res = await authenticatedFetch('/api/admin/interviews');
      if (!res.ok) throw new Error('Failed to fetch interviews');
      const data = await res.json();
      setInterviews(data);
    } catch (err) {
      setInterviews([]);
    }
    setLoading(false);
  };

  useEffect(() => {
    fetchInterviews();
  }, []);

  const handleApprove = async (id) => {
    await authenticatedFetch(`/api/admin/interviews/${id}/approve`, {
      method: 'PUT',
    });
    fetchInterviews();
  };

  const handleReject = async (id) => {
    await authenticatedFetch(`/api/admin/interviews/${id}/reject`, {
      method: 'PUT',
    });
    fetchInterviews();
  };

  return (
    <div style={{ display: 'flex', minHeight: '100vh', background: '#f0fdf4' }}>
      <Sidebar />
      <div style={{ flex: 1, padding: '2rem', background: '#fff', minHeight: '100vh' }}>
        <h2 style={{ fontSize: '2rem', fontWeight: 700, marginBottom: '2rem', color: '#16a34a' }}>Transcripts</h2>
        <TableContainer component={Paper} elevation={2} sx={{ borderRadius: 3, boxShadow: 3 }}>
          <Table>
            <TableHead>
              <TableRow sx={{ background: 'linear-gradient(90deg, #bbf7d0 0%, #f0fdf4 100%)' }}>
                <TableCell sx={{ color: '#166534', fontWeight: 700 }}>Position Name</TableCell>
                <TableCell sx={{ color: '#166534', fontWeight: 700 }}>Candidate Email</TableCell>
                <TableCell sx={{ color: '#166534', fontWeight: 700 }}>Review Status</TableCell>
                <TableCell sx={{ color: '#166534', fontWeight: 700 }}>Actions</TableCell>
                <TableCell sx={{ color: '#166534', fontWeight: 700 }}>Review</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {interviews.map((app, index) => (
                <TableRow
                  key={index}
                  sx={{
                    backgroundColor: index % 2 === 0 ? '#fff' : '#f0fdf4',
                    transition: 'background 0.2s',
                    '&:hover': { backgroundColor: '#bbf7d0' },
                  }}
                >
                  <TableCell sx={{ fontWeight: 600 }}>{app.positionName}</TableCell>
                  <TableCell>{app.email}</TableCell>
                  <TableCell>{getReviewStatusBadge(app.reviewStatus)}</TableCell>
                  <TableCell>
                    <Button
                      size="small"
                      variant="outlined"
                      sx={{ color: '#16a34a', borderColor: '#16a34a', fontWeight: 600, mr: 1, cursor: 'pointer', '&:hover': { background: '#f0fdf4', borderColor: '#16a34a' } }}
                      onClick={() => { setSelectedInterview(app); setModalOpen(true); }}
                    >
                      View Details
                    </Button>
                  </TableCell>
                  <TableCell>
                    <Button
                      size="small"
                      variant="contained"
                      sx={{ background: '#bbf7d0', color: '#166534', fontWeight: 700, mr: 1, cursor: 'pointer', '&:hover': { background: '#4ade80', color: '#166534' } }}
                      onClick={() => handleApprove(app._id)}
                      disabled={app.reviewStatus === 'approved'}
                    >
                      Approve
                    </Button>
                    <Button
                      size="small"
                      variant="contained"
                      sx={{ background: '#fecaca', color: '#991b1b', fontWeight: 700, cursor: 'pointer', '&:hover': { background: '#f87171', color: '#991b1b' } }}
                      onClick={() => handleReject(app._id)}
                      disabled={app.reviewStatus === 'rejected'}
                    >
                      Reject
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>
        <Dialog open={modalOpen} onClose={() => setModalOpen(false)} maxWidth="md" fullWidth>
          <DialogTitle sx={{ color: '#16a34a', fontWeight: 700 }}>Transcript Details</DialogTitle>
          <DialogContent dividers sx={{ py: 3 }}>
            {selectedInterview && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '1.2rem' }}>
                <div><strong>Position Name:</strong> {selectedInterview.positionName}</div>
                <div><strong>Position Description:</strong> {selectedInterview.positionDescription}</div>
                <div><strong>Candidate Email:</strong> {selectedInterview.email}</div>
                <div><strong>Review Status:</strong> {getReviewStatusBadge(selectedInterview.reviewStatus)}</div>
                <div><strong>Summary:</strong>
                  <div style={{ background: '#f0fdf4', border: '1px solid #bbf7d0', borderRadius: 8, padding: 8, marginTop: 4 }}>
                    {typeof selectedInterview.summary === 'string' ? selectedInterview.summary : JSON.stringify(selectedInterview.summary, null, 2)}
                  </div>
                </div>
                <div><strong>Transcript:</strong>
                  <div style={{ background: '#f1f5f9', border: '1px solid #e5e7eb', borderRadius: 8, padding: 8, marginTop: 4, maxHeight: 240, overflowY: 'auto' }}>
                    {typeof selectedInterview.transcript === 'string' ? selectedInterview.transcript : JSON.stringify(selectedInterview.transcript, null, 2)}
                  </div>
                </div>
              </div>
            )}
          </DialogContent>
          <DialogActions>
            <Button onClick={() => setModalOpen(false)} variant="outlined" sx={{ borderColor: '#16a34a', color: '#16a34a', fontWeight: 600, '&:hover': { background: '#f0fdf4', borderColor: '#16a34a' }, cursor: 'pointer' }}>
              Close
            </Button>
          </DialogActions>
        </Dialog>
      </div>
    </div>
  );
};

export default AdminTranscripts; 