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

const Companies = () => {
  const [companies, setCompanies] = useState([]);
  const [loading, setLoading] = useState(true);
  const [showAddModal, setShowAddModal] = useState(false);
  const [showEditModal, setShowEditModal] = useState(false);
  const [showDeleteModal, setShowDeleteModal] = useState(false);
  const [newCompany, setNewCompany] = useState({ name: '' });
  const [editCompany, setEditCompany] = useState({ id: '', name: '' });
  const [deleteId, setDeleteId] = useState("");
  const [page, setPage] = useState(1);

  // Fetch companies
  const fetchCompanies = async () => {
    setLoading(true);
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
    setLoading(false);
  };

  useEffect(() => {
    fetchCompanies();
  }, []);

  // Pagination logic
  const totalPages = Math.ceil(companies.length / PAGE_SIZE);
  const paginatedCompanies = companies.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE);

  // Modal animation classes
  const modalBgClass = "fixed inset-0 bg-black bg-opacity-40 flex items-center justify-center z-50 transition-opacity duration-200";
  const modalCardClass = "bg-white rounded-2xl shadow-2xl w-full max-w-sm transition-all duration-300";

  // Add company
  const handleAdd = async (e) => {
    e.preventDefault();
    const { name } = newCompany;
    if (!name) {
      toast.error("Name is required");
      return;
    }
    try {
      const res = await authenticatedFetch("/api/companies", {
        method: "POST",
        body: JSON.stringify(newCompany)
      });
      if (res.ok) {
        toast.success("Company added");
        setShowAddModal(false);
        setNewCompany({ name: '' });
        fetchCompanies();
      } else {
        const data = await res.json();
        toast.error(data.message || "Failed to add company");
      }
    } catch {
      toast.error("Network error");
    }
  };

  // Edit company
  const handleEdit = async (e) => {
    e.preventDefault();
    const { name } = editCompany;
    if (!name) {
      toast.error("Name is required");
      return;
    }
    try {
      const res = await authenticatedFetch(`/api/companies/${editCompany.id}`, {
        method: "PUT",
        body: JSON.stringify({ name: editCompany.name })
      });
      if (res.ok) {
        toast.success("Company updated");
        setShowEditModal(false);
        setEditCompany({ id: '', name: '' });
        fetchCompanies();
      } else {
        const data = await res.json();
        toast.error(data.message || "Failed to update company");
      }
    } catch {
      toast.error("Network error");
    }
  };

  // Delete company
  const handleDelete = async () => {
    try {
      const res = await authenticatedFetch(`/api/companies/${deleteId}`, {
        method: "DELETE"
      });
      if (res.ok) {
        toast.success("Company deleted");
        setShowDeleteModal(false);
        setDeleteId("");
        fetchCompanies();
      } else {
        const data = await res.json();
        toast.error(data.message || "Failed to delete company");
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
            <h2 className="text-2xl font-bold text-blue-700">Companies</h2>
            <Button
              startIcon={<AddIcon />}
              sx={{
                background: 'linear-gradient(90deg, #14b8a6 0%, #5eead4 100%)',
                color: '#fff',
                boxShadow: 2,
                px: 3,
                py: 1.5,
                borderRadius: 2,
                fontWeight: 600,
                fontSize: '1rem',
                textTransform: 'none',
                '&:hover': {
                  background: 'linear-gradient(90deg, #0d9488 0%, #2dd4bf 100%)',
                },
                cursor: 'pointer',
              }}
              onClick={() => setShowAddModal(true)}
            >
              Add Company
            </Button>
          </div>
          <div className="overflow-x-auto rounded-xl border border-gray-100">
            <table className="min-w-full text-sm text-left rounded-xl overflow-hidden shadow-sm">
              <thead className="bg-gradient-to-r from-teal-200 via-teal-100 to-teal-50 text-teal-800">
                <tr>
                  <th className="py-3 px-5">Company ID</th>
                  <th className="py-3 px-5">Name</th>
                  <th className="py-3 px-5">Actions</th>
                </tr>
              </thead>
              <tbody>
                {loading ? (
                  <tr><td colSpan="3" className="py-6 text-center">Loading...</td></tr>
                ) : paginatedCompanies.length === 0 ? (
                  <tr><td colSpan="3" className="py-6 text-center text-gray-400">No companies found.</td></tr>
                ) : (
                  paginatedCompanies.map((company, idx) => (
                    <tr key={company.id} className={`transition ${idx % 2 === 0 ? 'bg-white' : 'bg-teal-50'} hover:bg-[#CCFBF1] rounded-xl group`}>
                      <td className="py-3 px-5 font-mono text-xs rounded-l-xl">{company.id}</td>
                      <td className="py-3 px-5">{company.name}</td>
                      <td className="py-3 px-5 flex gap-2">
                        <button
                          className="px-3 py-1 text-sm text-blue-600 border border-blue-600 rounded-lg hover:bg-blue-50 transition cursor-pointer"
                          onClick={() => { setEditCompany({ id: company.id, name: company.name }); setShowEditModal(true); }}
                        >
                          <Edit className="w-4 h-4 inline" /> Edit
                        </button>
                        <button
                          className="px-3 py-1 text-sm text-red-600 border border-red-600 rounded-lg hover:bg-red-50 transition cursor-pointer"
                          onClick={() => { setDeleteId(company.id); setShowDeleteModal(true); }}
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
          <Dialog open={showAddModal} onClose={() => setShowAddModal(false)} maxWidth="sm" fullWidth>
            <DialogTitle sx={{ color: '#0f766e', fontWeight: 700 }}>Add Company</DialogTitle>
            <DialogContent dividers>
              <form className="flex flex-col gap-4" onSubmit={handleAdd}>
                <TextField label="Name" variant="outlined" fullWidth required value={newCompany.name} onChange={e => setNewCompany({ ...newCompany, name: e.target.value })} autoFocus />
              </form>
            </DialogContent>
            <DialogActions>
              <Button onClick={() => setShowAddModal(false)} color="secondary" variant="outlined" sx={{ borderColor: '#14b8a6', color: '#0f766e', '&:hover': { borderColor: '#0d9488', background: '#f0fdfa' } }}>Cancel</Button>
              <Button onClick={handleAdd} color="primary" variant="contained" type="submit" sx={{ background: 'linear-gradient(90deg, #14b8a6 0%, #5eead4 100%)', color: '#fff', boxShadow: 2, '&:hover': { background: 'linear-gradient(90deg, #0d9488 0%, #2dd4bf 100%)' } }}>Add</Button>
            </DialogActions>
          </Dialog>

          {/* Edit Modal */}
          <Dialog open={showEditModal} onClose={() => setShowEditModal(false)} maxWidth="sm" fullWidth>
            <DialogTitle sx={{ color: '#0f766e', fontWeight: 700 }}>Edit Company</DialogTitle>
            <DialogContent dividers>
              <form className="flex flex-col gap-4" onSubmit={handleEdit}>
                <TextField label="Name" variant="outlined" fullWidth required value={editCompany.name} onChange={e => setEditCompany({ ...editCompany, name: e.target.value })} autoFocus />
              </form>
            </DialogContent>
            <DialogActions>
              <Button onClick={() => setShowEditModal(false)} color="secondary" variant="outlined" sx={{ borderColor: '#14b8a6', color: '#0f766e', '&:hover': { borderColor: '#0d9488', background: '#f0fdfa' } }}>Cancel</Button>
              <Button onClick={handleEdit} color="primary" variant="contained" type="submit" sx={{ background: 'linear-gradient(90deg, #14b8a6 0%, #5eead4 100%)', color: '#fff', boxShadow: 2, '&:hover': { background: 'linear-gradient(90deg, #0d9488 0%, #2dd4bf 100%)' } }}>Update</Button>
            </DialogActions>
          </Dialog>

          {/* Delete Confirmation Modal */}
          <Dialog open={showDeleteModal} onClose={() => setShowDeleteModal(false)} maxWidth="sm" fullWidth>
            <DialogTitle sx={{ color: '#0f766e', fontWeight: 700 }}>Delete Company</DialogTitle>
            <DialogContent dividers>
              <p className="mb-6">Are you sure you want to delete this company?</p>
            </DialogContent>
            <DialogActions>
              <Button onClick={() => setShowDeleteModal(false)} color="secondary" variant="outlined" sx={{ borderColor: '#14b8a6', color: '#0f766e', '&:hover': { borderColor: '#0d9488', background: '#f0fdfa' } }}>Cancel</Button>
              <Button onClick={handleDelete} color="primary" variant="contained" type="submit" sx={{ background: 'linear-gradient(90deg, #14b8a6 0%, #5eead4 100%)', color: '#fff', boxShadow: 2, '&:hover': { background: 'linear-gradient(90deg, #0d9488 0%, #2dd4bf 100%)' } }}>Delete</Button>
            </DialogActions>
          </Dialog>
        </div>
      </div>
    </div>
  );
};

export default Companies; 