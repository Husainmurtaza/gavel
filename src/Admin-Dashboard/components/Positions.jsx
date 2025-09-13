import React, { useEffect, useState } from 'react';
import { Card, Col, Row, Progress, Table } from 'antd';
import {
  WalletOutlined,
  GlobalOutlined,
  ClockCircleOutlined,
  ShoppingCartOutlined,
} from '@ant-design/icons';
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
import FormControl from '@mui/material/FormControl';
import InputLabel from '@mui/material/InputLabel';
import Select from '@mui/material/Select';
import MenuItem from '@mui/material/MenuItem';

const PAGE_SIZE = 15;

const Positions = () => {
  const [positions, setPositions] = useState([]);
  const [loading, setLoading] = useState(true);
  const [showAddModal, setShowAddModal] = useState(false);
  const [showEditModal, setShowEditModal] = useState(false);
  const [showDeleteModal, setShowDeleteModal] = useState(false);
  const [newPosition, setNewPosition] = useState("");
  const [newProjectDescription, setNewProjectDescription] = useState("");
  const [editPosition, setEditPosition] = useState({ id: "", name: "", projectDescription: "" });
  const [deleteId, setDeleteId] = useState("");
  const [page, setPage] = useState(1);
  const [companies, setCompanies] = useState([]);
  const [newCompany, setNewCompany] = useState("");
  const [newRedFlag, setNewRedFlag] = useState("");
  const [editCompany, setEditCompany] = useState("");
  const [editRedFlag, setEditRedFlag] = useState("");
  const [showViewModal, setShowViewModal] = useState(false);
  const [viewPosition, setViewPosition] = useState(null);

  // Fetch positions
  const fetchPositions = async () => {
    setLoading(true);
    try {
      const res = await authenticatedFetch("/api/positions");
      if (res.ok) {
        const data = await res.json();
        setPositions(data);
      } else {
        setPositions([]);
      }
    } catch {
      setPositions([]);
    }
    setLoading(false);
  };

  // Fetch companies
  const fetchCompanies = async () => {
    try {
      const res = await authenticatedFetch("/api/companies");
      if (res.ok) {
        const data = await res.json();
        setCompanies(data);
      } else {
        setCompanies([]);
      }
    } catch {
      setCompanies([]);
    }
  };

  useEffect(() => {
    fetchPositions();
    fetchCompanies();
  }, []);

  // Pagination logic
  const totalPages = Math.ceil(positions.length / PAGE_SIZE);
  const paginatedPositions = positions.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE);

  // Modal animation classes
  const modalBgClass = "fixed inset-0 bg-black bg-opacity-40 flex items-center justify-center z-50 transition-opacity duration-200";
  const modalCardClass = "bg-white rounded-2xl shadow-2xl w-full max-w-sm transition-all duration-300";

  // Add position
  const handleAdd = async (e) => {
    e.preventDefault();
    if (!newPosition.trim()) {
      toast.error("Position Name is required");
      return;
    }
    try {
      const res = await authenticatedFetch("/api/positions", {
        method: "POST",
        body: JSON.stringify({ name: newPosition, projectDescription: newProjectDescription, company: newCompany, redFlag: newRedFlag })
      });
      if (res.ok) {
        toast.success("Position added");
        setShowAddModal(false);
        setNewPosition("");
        setNewProjectDescription("");
        setNewCompany("");
        setNewRedFlag("");
        fetchPositions();
      } else {
        const data = await res.json();
        toast.error(data.message || "Failed to add position");
      }
    } catch {
      toast.error("Network error");
    }
  };

  // Edit position
  const handleEdit = async (e) => {
    e.preventDefault();
    if (!editPosition.name.trim()) {
      toast.error("Position Name is required");
      return;
    }
    try {
      const res = await authenticatedFetch(`/api/positions/${editPosition.id}`, {
        method: "PUT",
        body: JSON.stringify({ name: editPosition.name, projectDescription: editPosition.projectDescription, company: editCompany, redFlag: editRedFlag })
      });
      if (res.ok) {
        toast.success("Position updated");
        setShowEditModal(false);
        setEditPosition({ id: "", name: "", projectDescription: "" });
        fetchPositions();
      } else {
        const data = await res.json();
        toast.error(data.message || "Failed to update position");
      }
    } catch {
      toast.error("Network error");
    }
  };

  // Delete position
  const handleDelete = async () => {
    try {
      const res = await authenticatedFetch(`/api/positions/${deleteId}`, {
        method: "DELETE"
      });
      if (res.ok) {
        toast.success("Position deleted");
        setShowDeleteModal(false);
        setDeleteId("");
        fetchPositions();
      } else {
        const data = await res.json();
        toast.error(data.message || "Failed to delete position");
      }
    } catch {
      toast.error("Network error");
    }
  };

  // Pagination controls
  const Pagination = () => (
    <div className="flex justify-center items-center gap-2 mt-6">
      <button
        className="px-3 py-1 rounded border bg-gray-100 text-gray-700 hover:bg-gray-200 disabled:opacity-50"
        onClick={() => setPage(page - 1)}
        disabled={page === 1}
      >
        Prev
      </button>
      {Array.from({ length: totalPages }, (_, i) => (
        <button
          key={i + 1}
          className={`px-3 py-1 rounded border ${page === i + 1 ? 'bg-blue-600 text-white' : 'bg-gray-100 text-gray-700 hover:bg-gray-200'}`}
          onClick={() => setPage(i + 1)}
        >
          {i + 1}
        </button>
      ))}
      <button
        className="px-3 py-1 rounded border bg-gray-100 text-gray-700 hover:bg-gray-200 disabled:opacity-50"
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
            <h2 className="text-2xl font-bold text-blue-700">Positions</h2>
            <Button
              startIcon={<AddIcon />}
              sx={{
                background: 'linear-gradient(90deg, #f59e42 0%, #fbbf24 100%)',
                color: '#fff',
                boxShadow: 2,
                px: 3,
                py: 1.5,
                borderRadius: 2,
                fontWeight: 600,
                fontSize: '1rem',
                textTransform: 'none',
                '&:hover': {
                  background: 'linear-gradient(90deg, #ea580c 0%, #f59e42 100%)',
                },
                cursor: 'pointer',
              }}
              onClick={() => setShowAddModal(true)}
            >
              Add Position
            </Button>
          </div>
          <div className="overflow-x-auto rounded-xl border border-gray-100">
            <table className="min-w-full text-sm text-left rounded-xl overflow-hidden shadow-sm">
              <thead className="bg-gradient-to-r from-orange-200 via-orange-100 to-orange-50 text-orange-800">
                <tr>
                  <th className="py-3 px-5">Position ID</th>
                  <th className="py-3 px-5">Position Name</th>
                  <th className="py-3 px-5">Project Description</th>
                  <th className="py-3 px-5">Company</th>
                  <th className="py-3 px-5">Actions</th>
                  <th className="py-3 px-5">View Record</th>
                </tr>
              </thead>
              <tbody>
                {loading ? (
                  <tr><td colSpan="6" className="py-6 text-center">Loading...</td></tr>
                ) : paginatedPositions.length === 0 ? (
                  <tr><td colSpan="6" className="py-6 text-center text-gray-400">No positions found.</td></tr>
                ) : (
                  paginatedPositions.map((pos, idx) => (
                    <tr key={pos.id} className={`transition ${idx % 2 === 0 ? 'bg-white' : 'bg-orange-50'} hover:bg-[#FFEDD5] rounded-xl group`}>
                      <td className="py-3 px-5 font-mono text-xs rounded-l-xl">{pos.id}</td>
                      <td className="py-3 px-5">{pos.name}</td>
                      <td className="py-3 px-5">{pos.projectDescription && pos.projectDescription.length > 40 ? `${pos.projectDescription.slice(0, 40)}...` : pos.projectDescription}</td>
                      <td className="py-3 px-5">{companies.find(c => c.id === pos.company)?.name || ''}</td>
                      <td className="py-3 px-5 flex gap-2">
                        <button
                          className="px-3 py-1 text-sm text-blue-600 border border-blue-600 rounded-lg hover:bg-blue-50 transition cursor-pointer"
                          onClick={() => { setEditPosition({ id: pos.id, name: pos.name, projectDescription: pos.projectDescription || "" }); setShowEditModal(true); }}
                        >
                          <Edit className="w-4 h-4 inline" /> Edit
                        </button>
                        <button
                          className="px-3 py-1 text-sm text-red-600 border border-red-600 rounded-lg hover:bg-red-50 transition cursor-pointer"
                          onClick={() => { setDeleteId(pos.id); setShowDeleteModal(true); }}
                        >
                          <Trash2 className="w-4 h-4 inline" /> Delete
                        </button>
                      </td>
                      <td className="py-3 px-5">
                        <button className="px-3 py-1 text-sm text-green-600 border border-green-600 rounded-lg hover:bg-green-50 transition cursor-pointer" onClick={() => { setViewPosition(pos); setShowViewModal(true); }}>View</button>
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
            <Dialog open={showAddModal} onClose={() => setShowAddModal(false)} maxWidth="sm" fullWidth>
              <DialogTitle sx={{ color: '#ea580c', fontWeight: 700 }}>Add New Position</DialogTitle>
              <DialogContent dividers>
                <form className="flex flex-col gap-4" onSubmit={handleAdd}>
                  <TextField label="Position Name" variant="outlined" fullWidth required value={newPosition} onChange={e => setNewPosition(e.target.value)} />
                  <TextField label="Project Description" variant="outlined" fullWidth multiline rows={4} value={newProjectDescription} onChange={e => setNewProjectDescription(e.target.value)} />
                  <FormControl fullWidth required>
                    <InputLabel id="add-company-label">Company</InputLabel>
                    <Select
                      labelId="add-company-label"
                      value={newCompany}
                      label="Company"
                      onChange={e => setNewCompany(e.target.value)}
                    >
                      {companies.map(company => (
                        <MenuItem key={company.id || company._id} value={company.id || company._id}>{company.name}</MenuItem>
                      ))}
                    </Select>
                  </FormControl>
                  <TextField label="Red Flag (optional)" variant="outlined" fullWidth value={newRedFlag} onChange={e => setNewRedFlag(e.target.value)} />
                </form>
              </DialogContent>
              <DialogActions>
                <Button onClick={() => setShowAddModal(false)} variant="outlined" sx={{ borderColor: '#f59e42', color: '#ea580c', '&:hover': { borderColor: '#ea580c', background: '#fff7ed' }, cursor: 'pointer' }}>Cancel</Button>
                <Button onClick={handleAdd} sx={{ background: 'linear-gradient(90deg, #f59e42 0%, #fbbf24 100%)', color: '#fff', boxShadow: 2, '&:hover': { background: 'linear-gradient(90deg, #ea580c 0%, #f59e42 100%)' }, cursor: 'pointer' }} type="submit">Add Position</Button>
              </DialogActions>
            </Dialog>
          )}

          {/* Edit Modal */}
          {showEditModal && (
            <Dialog open={showEditModal} onClose={() => setShowEditModal(false)} maxWidth="sm" fullWidth>
              <DialogTitle sx={{ color: '#ea580c', fontWeight: 700 }}>Edit Position</DialogTitle>
              <DialogContent dividers>
                <form className="flex flex-col gap-4" onSubmit={handleEdit}>
                  <TextField label="Position Name" variant="outlined" fullWidth required value={editPosition.name} onChange={e => setEditPosition({ ...editPosition, name: e.target.value })} />
                  <TextField label="Project Description" variant="outlined" fullWidth multiline rows={4} value={editPosition.projectDescription} onChange={e => setEditPosition({ ...editPosition, projectDescription: e.target.value })} />
                  <FormControl fullWidth required>
                    <InputLabel id="edit-company-label">Company</InputLabel>
                    <Select
                      labelId="edit-company-label"
                      value={editCompany}
                      label="Company"
                      onChange={e => setEditCompany(e.target.value)}
                    >
                      {companies.map(company => (
                        <MenuItem key={company.id || company._id} value={company.id || company._id}>{company.name}</MenuItem>
                      ))}
                    </Select>
                  </FormControl>
                  <TextField label="Red Flag (optional)" variant="outlined" fullWidth value={editRedFlag} onChange={e => setEditRedFlag(e.target.value)} />
                </form>
              </DialogContent>
              <DialogActions>
                <Button onClick={() => setShowEditModal(false)} variant="outlined" sx={{ borderColor: '#f59e42', color: '#ea580c', '&:hover': { borderColor: '#ea580c', background: '#fff7ed' }, cursor: 'pointer' }}>Cancel</Button>
                <Button onClick={handleEdit} sx={{ background: 'linear-gradient(90deg, #f59e42 0%, #fbbf24 100%)', color: '#fff', boxShadow: 2, '&:hover': { background: 'linear-gradient(90deg, #ea580c 0%, #f59e42 100%)' }, cursor: 'pointer' }} type="submit">Update</Button>
              </DialogActions>
            </Dialog>
          )}

          {/* Delete Confirmation Modal */}
          {showDeleteModal && (
            <Dialog open={showDeleteModal} onClose={() => setShowDeleteModal(false)} maxWidth="sm" fullWidth>
              <DialogTitle sx={{ color: '#ea580c', fontWeight: 700 }}>Delete Position</DialogTitle>
              <DialogContent dividers>
                <p className="mb-6">Are you sure you want to delete this position?</p>
              </DialogContent>
              <DialogActions>
                <Button onClick={() => setShowDeleteModal(false)} variant="outlined" sx={{ borderColor: '#f59e42', color: '#ea580c', '&:hover': { borderColor: '#ea580c', background: '#fff7ed' }, cursor: 'pointer' }}>Cancel</Button>
                <Button onClick={handleDelete} color="error" variant="contained" sx={{ cursor: 'pointer' }}>Delete</Button>
              </DialogActions>
            </Dialog>
          )}

          {/* View Record Modal */}
          {showViewModal && viewPosition && (
            <Dialog open={showViewModal} onClose={() => setShowViewModal(false)} maxWidth="sm" fullWidth>
              <DialogTitle sx={{ color: '#ea580c', fontWeight: 700 }}>Position Details</DialogTitle>
              <DialogContent dividers>
                <div className="flex flex-col gap-4">
                  <TextField
                    label="Position Name"
                    variant="outlined"
                    fullWidth
                    value={viewPosition.name}
                    InputProps={{ readOnly: true }}
                  />
                  <TextField
                    label="Project Description"
                    variant="outlined"
                    fullWidth
                    multiline
                    rows={4}
                    value={viewPosition.projectDescription}
                    InputProps={{ readOnly: true }}
                  />
                  <TextField
                    label="Company"
                    variant="outlined"
                    fullWidth
                    value={companies.find(c => c.id === viewPosition.company)?.name || ''}
                    InputProps={{ readOnly: true }}
                  />
                  <TextField
                    label="Red Flag"
                    variant="outlined"
                    fullWidth
                    value={viewPosition.redFlag || ''}
                    InputProps={{ readOnly: true }}
                  />
                </div>
              </DialogContent>
              <DialogActions>
                <Button onClick={() => setShowViewModal(false)} variant="outlined" sx={{ borderColor: '#f59e42', color: '#ea580c', '&:hover': { borderColor: '#ea580c', background: '#fff7ed' }, cursor: 'pointer' }}>Close</Button>
              </DialogActions>
            </Dialog>
          )}
        </div>
      </div>
    </div>
  );
};

export default Positions;
