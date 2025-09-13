import React, { useEffect, useState } from 'react';
import Sidebar from './Sidebar';
import { Plus, Edit, Trash2, X } from 'lucide-react';
import { toast, ToastContainer } from 'react-toastify';
import { authenticatedFetch } from '../../utils/api';
import 'react-toastify/dist/ReactToastify.css';
import Dialog from '@mui/material/Dialog';
import DialogTitle from '@mui/material/DialogTitle';
import DialogContent from '@mui/material/DialogContent';
import DialogActions from '@mui/material/DialogActions';
import TextField from '@mui/material/TextField';
import Button from '@mui/material/Button';
import AddIcon from '@mui/icons-material/Add';

const PAGE_SIZE = 15;

const Candidates = () => {
  const [candidates, setCandidates] = useState([]);
  const [loading, setLoading] = useState(true);
  const [showAddModal, setShowAddModal] = useState(false);
  const [showEditModal, setShowEditModal] = useState(false);
  const [showDeleteModal, setShowDeleteModal] = useState(false);
  const [newCandidate, setNewCandidate] = useState({ firstName: '', lastName: '', email: '', phone: '', password: '' });
  const [editCandidate, setEditCandidate] = useState({ id: '', firstName: '', lastName: '', email: '', phone: '' });
  const [deleteId, setDeleteId] = useState("");
  const [page, setPage] = useState(1);

  // Fetch candidates
  const fetchCandidates = async () => {
    setLoading(true);
    try {
      const res = await authenticatedFetch("/api/candidates");
      if (res.ok) {
        const data = await res.json();
        setCandidates(data);
      } else {
        setCandidates([]);
      }
    } catch {
      setCandidates([]);
    }
    setLoading(false);
  };

  useEffect(() => {
    fetchCandidates();
  }, []);

  // Pagination logic
  const totalPages = Math.ceil(candidates.length / PAGE_SIZE);
  const paginatedCandidates = candidates.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE);

  // Modal animation classes
  const modalBgClass = "fixed inset-0 bg-black bg-opacity-40 flex items-center justify-center z-50 transition-opacity duration-200";
  const modalCardClass = "bg-white rounded-2xl shadow-2xl w-full max-w-sm transition-all duration-300";

  // Add candidate
  const handleAdd = async (e) => {
    e.preventDefault();
    const { firstName, lastName, email, phone, password } = newCandidate;
    if (!firstName || !lastName || !email || !phone || !password) {
      toast.error("All fields are required");
      return;
    }
    try {
      const res = await authenticatedFetch("/api/candidates", {
        method: "POST",
        body: JSON.stringify(newCandidate)
      });
      if (res.ok) {
        toast.success("Candidate added");
        setShowAddModal(false);
        setNewCandidate({ firstName: '', lastName: '', email: '', phone: '', password: '' });
        fetchCandidates();
      } else {
        const data = await res.json();
        toast.error(data.message || "Failed to add candidate");
      }
    } catch {
      toast.error("Network error");
    }
  };

  // Edit candidate
  const handleEdit = async (e) => {
    e.preventDefault();
    const { firstName, lastName, email, phone } = editCandidate;
    if (!firstName || !lastName || !email || !phone) {
      toast.error("All fields are required");
      return;
    }
    try {
      const res = await authenticatedFetch(`/api/candidates/${editCandidate.id}`, {
        method: "PUT",
        body: JSON.stringify({ firstName, lastName, email, phone })
      });
      if (res.ok) {
        toast.success("Candidate updated");
        setShowEditModal(false);
        setEditCandidate({ id: '', firstName: '', lastName: '', email: '', phone: '' });
        fetchCandidates();
      } else {
        const data = await res.json();
        toast.error(data.message || "Failed to update candidate");
      }
    } catch {
      toast.error("Network error");
    }
  };

  // Delete candidate
  const handleDelete = async () => {
    try {
      const res = await authenticatedFetch(`/api/candidates/${deleteId}`, {
        method: "DELETE"
      });
      if (res.ok) {
        toast.success("Candidate deleted");
        setShowDeleteModal(false);
        setDeleteId("");
        fetchCandidates();
      } else {
        const data = await res.json();
        toast.error(data.message || "Failed to delete candidate");
      }
    } catch {
      toast.error("Network error");
    }
  };

  // Pagination controls
  const Pagination = () => (
    <div className="flex justify-center items-center gap-2 mt-6">
      <button
        className="px-3 py-1 rounded border bg-gray-100 text-gray-700 hover:bg-gray-200 disabled:opacity-50 cursor-pointer"
        onClick={() => setPage(page - 1)}
        disabled={page === 1}
      >
        Prev
      </button>
      {Array.from({ length: totalPages }, (_, i) => (
        <button
          key={i + 1}
          className={`px-3 py-1 rounded border cursor-pointer ${page === i + 1 ? 'bg-blue-600 text-white' : 'bg-gray-100 text-gray-700 hover:bg-gray-200'}`}
          onClick={() => setPage(i + 1)}
        >
          {i + 1}
        </button>
      ))}
      <button
        className="px-3 py-1 rounded border bg-gray-100 text-gray-700 hover:bg-gray-200 disabled:opacity-50 cursor-pointer"
        onClick={() => setPage(page + 1)}
        disabled={page === totalPages}
      >
        Next
      </button>
    </div>
  );

  return (
    <div className='flex'>
      <Sidebar />
      <div className="flex-1 p-4 bg-[#f8f9fa] min-h-screen">
        <div className="bg-white p-6 rounded-2xl shadow-lg w-full">
          <ToastContainer position="top-right" autoClose={3000} />
          <div className="flex justify-between items-center mb-6">
            <h2 className="text-2xl font-bold text-blue-700">Candidates</h2>
            <Button
              startIcon={<AddIcon />}
              sx={{
                background: 'linear-gradient(90deg, #a21caf 0%, #f472b6 100%)',
                color: '#fff',
                boxShadow: 2,
                px: 3,
                py: 1.5,
                borderRadius: 2,
                fontWeight: 600,
                fontSize: '1rem',
                textTransform: 'none',
                '&:hover': {
                  background: 'linear-gradient(90deg, #701a75 0%, #e879f9 100%)',
                },
                cursor: 'pointer',
              }}
              onClick={() => setShowAddModal(true)}
            >
              Add Candidate
            </Button>
          </div>
          <div className="overflow-x-auto rounded-xl border border-gray-100">
            <table className="min-w-full text-sm text-left rounded-xl overflow-hidden shadow-sm">
              <thead className="bg-gradient-to-r from-purple-200 via-purple-100 to-pink-50 text-purple-800">
                <tr>
                  <th className="py-3 px-5">Candidate ID</th>
                  <th className="py-3 px-5">First Name</th>
                  <th className="py-3 px-5">Last Name</th>
                  <th className="py-3 px-5">Email</th>
                  <th className="py-3 px-5">Phone</th>
                  <th className="py-3 px-5">Actions</th>
                </tr>
              </thead>
              <tbody>
                {loading ? (
                  <tr><td colSpan="6" className="py-6 text-center">Loading...</td></tr>
                ) : paginatedCandidates.length === 0 ? (
                  <tr><td colSpan="6" className="py-6 text-center text-gray-400">No candidates found.</td></tr>
                ) : (
                  paginatedCandidates.map((candidate, idx) => (
                    <tr key={candidate.id} className={`transition ${idx % 2 === 0 ? 'bg-white' : 'bg-purple-50'} hover:bg-purple-100 rounded-xl group`}>
                      <td className="py-3 px-5 font-mono text-xs rounded-l-xl">{candidate.id}</td>
                      <td className="py-3 px-5">{candidate.firstName}</td>
                      <td className="py-3 px-5">{candidate.lastName}</td>
                      <td className="py-3 px-5">{candidate.email}</td>
                      <td className="py-3 px-5">{candidate.phone}</td>
                      <td className="py-3 px-5 flex gap-2">
                        <button
                          className="px-3 py-1 text-sm text-blue-600 border border-blue-600 rounded-lg hover:bg-blue-50 transition cursor-pointer"
                          onClick={() => { setEditCandidate({ id: candidate.id, firstName: candidate.firstName, lastName: candidate.lastName, email: candidate.email, phone: candidate.phone }); setShowEditModal(true); }}
                        >
                          <Edit className="w-4 h-4 inline" /> Edit
                        </button>
                        <button
                          className="px-3 py-1 text-sm text-red-600 border border-red-600 rounded-lg hover:bg-red-50 transition cursor-pointer"
                          onClick={() => { setDeleteId(candidate.id); setShowDeleteModal(true); }}
                        >
                          <Trash2 className="w-4 h-4 inline" /> Delete
                        </button>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
          {totalPages > 1 && <Pagination />}

          {/* Add Modal */}
          {showAddModal && (
            <Dialog open={showAddModal} onClose={() => setShowAddModal(false)}>
              <DialogTitle className=" text-[#AF4CBA] text-center rounded-t-2xl px-6 py-5">Add Candidate</DialogTitle>
              <DialogContent>
                <form onSubmit={handleAdd} className="px-6 py-6">
                  <TextField
                    label="First Name"
                    variant="outlined"
                    fullWidth
                    margin="normal"
                    value={newCandidate.firstName}
                    onChange={e => setNewCandidate({ ...newCandidate, firstName: e.target.value })}
                    autoFocus
                  />
                  <TextField
                    label="Last Name"
                    variant="outlined"
                    fullWidth
                    margin="normal"
                    value={newCandidate.lastName}
                    onChange={e => setNewCandidate({ ...newCandidate, lastName: e.target.value })}
                  />
                  <TextField
                    label="Email"
                    variant="outlined"
                    fullWidth
                    margin="normal"
                    value={newCandidate.email}
                    onChange={e => setNewCandidate({ ...newCandidate, email: e.target.value })}
                  />
                  <TextField
                    label="Phone"
                    variant="outlined"
                    fullWidth
                    margin="normal"
                    value={newCandidate.phone}
                    onChange={e => setNewCandidate({ ...newCandidate, phone: e.target.value })}
                  />
                  <TextField
                    label="Password"
                    variant="outlined"
                    fullWidth
                    margin="normal"
                    value={newCandidate.password}
                    onChange={e => setNewCandidate({ ...newCandidate, password: e.target.value })}
                  />
                </form>
              </DialogContent>
              <DialogActions className="px-6 py-6">
                <Button onClick={() => setShowAddModal(false)} variant="outlined" sx={{ borderColor: '#a21caf', color: '#a21caf', '&:hover': { borderColor: '#701a75', background: '#f3e8ff' } }}>Cancel</Button>
                <Button type="submit" sx={{ background: 'linear-gradient(90deg, #a21caf 0%, #f472b6 100%)', color: '#fff', fontWeight: 600, '&:hover': { background: 'linear-gradient(90deg, #701a75 0%, #e879f9 100%)' } }}>Save</Button>
              </DialogActions>
            </Dialog>
          )}

          {/* Edit Modal */}
          {showEditModal && (
            <Dialog open={showEditModal} onClose={() => setShowEditModal(false)}>
              <DialogTitle className="bg-[#232e3c] text-white rounded-t-2xl px-6 py-5">Edit Candidate</DialogTitle>
              <DialogContent>
                <form onSubmit={handleEdit} className="px-6 py-6">
                  <TextField
                    label="First Name"
                    variant="outlined"
                    fullWidth
                    margin="normal"
                    value={editCandidate.firstName}
                    onChange={e => setEditCandidate({ ...editCandidate, firstName: e.target.value })}
                    autoFocus
                  />
                  <TextField
                    label="Last Name"
                    variant="outlined"
                    fullWidth
                    margin="normal"
                    value={editCandidate.lastName}
                    onChange={e => setEditCandidate({ ...editCandidate, lastName: e.target.value })}
                  />
                  <TextField
                    label="Email"
                    variant="outlined"
                    fullWidth
                    margin="normal"
                    value={editCandidate.email}
                    onChange={e => setEditCandidate({ ...editCandidate, email: e.target.value })}
                  />
                  <TextField
                    label="Phone"
                    variant="outlined"
                    fullWidth
                    margin="normal"
                    value={editCandidate.phone}
                    onChange={e => setEditCandidate({ ...editCandidate, phone: e.target.value })}
                  />
                </form>
              </DialogContent>
              <DialogActions className="px-6 py-6">
                <Button onClick={() => setShowEditModal(false)} variant="outlined" sx={{ borderColor: '#a21caf', color: '#a21caf', '&:hover': { borderColor: '#701a75', background: '#f3e8ff' } }}>Cancel</Button>
                <Button type="submit" sx={{ background: 'linear-gradient(90deg, #a21caf 0%, #f472b6 100%)', color: '#fff', fontWeight: 600, '&:hover': { background: 'linear-gradient(90deg, #701a75 0%, #e879f9 100%)' } }}>Save</Button>
              </DialogActions>
            </Dialog>
          )}

          {/* Delete Confirmation Modal */}
          {showDeleteModal && (
            <Dialog open={showDeleteModal} onClose={() => setShowDeleteModal(false)}>
              <DialogTitle className="bg-red-600 text-white rounded-t-2xl px-6 py-5">Delete Candidate</DialogTitle>
              <DialogContent>
                <div className="px-6 py-6">
                  <p className="mb-6">Are you sure you want to delete this candidate?</p>
                </div>
              </DialogContent>
              <DialogActions className="px-6 py-6">
                <Button onClick={() => setShowDeleteModal(false)} variant="outlined" sx={{ borderColor: '#a21caf', color: '#a21caf', '&:hover': { borderColor: '#701a75', background: '#f3e8ff' } }}>Cancel</Button>
                <Button onClick={handleDelete} variant="contained" color="error" sx={{ background: 'linear-gradient(90deg, #dc2626 0%, #991b1b 100%)', '&:hover': { background: 'linear-gradient(90deg, #991b1b 0%, #7f1d1d 100%)' } }}>Delete</Button>
              </DialogActions>
            </Dialog>
          )}
        </div>
      </div>
    </div>
  );
};

export default Candidates; 