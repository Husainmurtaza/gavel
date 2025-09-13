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
import Select from '@mui/material/Select';
import MenuItem from '@mui/material/MenuItem';
import InputLabel from '@mui/material/InputLabel';
import FormControl from '@mui/material/FormControl';
import AddIcon from '@mui/icons-material/Add';

const PAGE_SIZE = 15;

const Clients = () => {
  const [clients, setClients] = useState([]);
  const [companies, setCompanies] = useState([]);
  const [loading, setLoading] = useState(true);
  const [showAddModal, setShowAddModal] = useState(false);
  const [showEditModal, setShowEditModal] = useState(false);
  const [showDeleteModal, setShowDeleteModal] = useState(false);
  const [newClient, setNewClient] = useState({ firstName: '', lastName: '', email: '', phone: '', password: '', company: '' });
  const [editClient, setEditClient] = useState({ id: '', firstName: '', lastName: '', email: '', phone: '', company: '' });
  const [deleteId, setDeleteId] = useState("");
  const [page, setPage] = useState(1);

  // Fetch clients
  const fetchClients = async () => {
    setLoading(true);
    try {
      const res = await authenticatedFetch("/api/clients");
      if (res.ok) {
        const data = await res.json();
        setClients(data);
      } else {
        setClients([]);
      }
    } catch {
      setClients([]);
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
    fetchClients();
    fetchCompanies();
  }, []);

  // Pagination logic
  const totalPages = Math.ceil(clients.length / PAGE_SIZE);
  const paginatedClients = clients.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE);

  // Modal animation classes
  const modalBgClass = "fixed inset-0 bg-black bg-opacity-40 flex items-center justify-center z-50 transition-opacity duration-200";
  const modalCardClass = "bg-white rounded-2xl shadow-2xl w-full max-w-sm transition-all duration-300";

  // Add client
  const handleAdd = async (e) => {
    e.preventDefault();
    const { firstName, lastName, email, phone, password, company } = newClient;
    if (!firstName || !lastName || !email || !phone || !password) {
      toast.error("All fields are required");
      return;
    }
    try {
      const res = await authenticatedFetch("/api/clients", {
        method: "POST",
        body: JSON.stringify({ firstName, lastName, email, phone, password, company })
      });
      if (res.ok) {
        toast.success("Client added");
        setShowAddModal(false);
        setNewClient({ firstName: '', lastName: '', email: '', phone: '', password: '', company: '' });
        fetchClients();
      } else {
        const data = await res.json();
        toast.error(data.message || "Failed to add client");
      }
    } catch {
      toast.error("Network error");
    }
  };

  // Edit client
  const handleEdit = async (e) => {
    e.preventDefault();
    const { firstName, lastName, email, phone, company } = editClient;
    if (!firstName || !lastName || !email || !phone) {
      toast.error("All fields are required");
      return;
    }
    try {
      const res = await authenticatedFetch(`/api/clients/${editClient.id}`, {
        method: "PUT",
        body: JSON.stringify({ firstName, lastName, email, phone, company })
      });
      if (res.ok) {
        toast.success("Client updated");
        setShowEditModal(false);
        setEditClient({ id: '', firstName: '', lastName: '', email: '', phone: '', company: '' });
        fetchClients();
      } else {
        const data = await res.json();
        toast.error(data.message || "Failed to update client");
      }
    } catch {
      toast.error("Network error");
    }
  };

  // Delete client
  const handleDelete = async () => {
    try {
      const res = await authenticatedFetch(`/api/clients/${deleteId}`, {
        method: "DELETE"
      });
      if (res.ok) {
        toast.success('Client deleted successfully!');
        setShowDeleteModal(false);
        setDeleteId("");
        fetchClients();
      } else {
        const data = await res.json();
        toast.error(data.message || "Failed to delete client");
      }
    } catch {
      toast.error("Network error");
    }
  };

  // When opening the edit modal, ensure editClient.company is set to the company ID (not the whole object)
  const handleEditClick = (client) => {
    setEditClient({
      ...client,
      company: client.company?.id || client.company?._id || client.company || '',
    });
    setShowEditModal(true);
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
            <h2 className="text-2xl font-bold text-blue-700">Clients</h2>
            <Button
              startIcon={<AddIcon />}
              sx={{
                background: 'linear-gradient(90deg, #2563eb 0%, #60a5fa 100%)',
                color: '#fff',
                boxShadow: 2,
                px: 3,
                py: 1.5,
                borderRadius: 2,
                fontWeight: 600,
                fontSize: '1rem',
                textTransform: 'none',
                '&:hover': {
                  background: 'linear-gradient(90deg, #1e40af 0%, #3b82f6 100%)',
                },
                cursor: 'pointer',
              }}
              onClick={() => setShowAddModal(true)}
            >
              Add Client
            </Button>
          </div>
          <div className="overflow-x-auto rounded-xl border border-gray-100">
            <table className="min-w-full text-sm text-left rounded-xl overflow-hidden shadow-sm">
              <thead className="bg-gradient-to-r from-blue-200 via-blue-100 to-blue-50 text-blue-800">
                <tr>
                  <th className="py-3 px-5">Client ID</th>
                  <th className="py-3 px-5">First Name</th>
                  <th className="py-3 px-5">Last Name</th>
                  <th className="py-3 px-5">Email</th>
                  <th className="py-3 px-5">Phone</th>
                  <th className="py-3 px-5">Company</th>
                  <th className="py-3 px-5">Actions</th>
                </tr>
              </thead>
              <tbody>
                {loading ? (
                  <tr><td colSpan="7" className="py-6 text-center">Loading...</td></tr>
                ) : paginatedClients.length === 0 ? (
                  <tr><td colSpan="7" className="py-6 text-center text-gray-400">No clients found.</td></tr>
                ) : (
                  paginatedClients.map((client, idx) => (
                    <tr key={client.id} className={
                      (idx % 2 === 0 ? "bg-white" : "bg-blue-50") +
                      " hover:bg-blue-100 transition rounded-xl group"
                    }>
                      <td className="py-3 px-5 font-mono text-xs rounded-l-xl">{client.id}</td>
                      <td className="py-3 px-5">{client.firstName}</td>
                      <td className="py-3 px-5">{client.lastName}</td>
                      <td className="py-3 px-5">{client.email}</td>
                      <td className="py-3 px-5">{client.phone}</td>
                      <td className="py-3 px-5">{client.company ? client.company.name : ''}</td>
                      <td className="py-3 px-5 flex gap-2">
                        <button
                          className="px-3 py-1 text-sm text-blue-600 border border-blue-600 rounded-lg hover:bg-blue-50 transition cursor-pointer"
                          onClick={() => handleEditClick(client)}
                        >
                          <Edit className="w-4 h-4 inline" /> Edit
                        </button>
                        <button
                          className="px-3 py-1 text-sm text-red-600 border border-red-600 rounded-lg hover:bg-red-50 transition cursor-pointer"
                          onClick={() => { setDeleteId(client.id); setShowDeleteModal(true); }}
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
            <Dialog open={showAddModal} onClose={() => setShowAddModal(false)} maxWidth="sm" fullWidth>
              <DialogTitle className='text-[#316ADD]'>Add New Client</DialogTitle>
              <DialogContent dividers>
                <form className="flex flex-col gap-4" onSubmit={handleAdd}>
                  <TextField label="First Name" variant="outlined" fullWidth required value={newClient.firstName} onChange={e => setNewClient({ ...newClient, firstName: e.target.value })} />
                  <TextField label="Last Name" variant="outlined" fullWidth required value={newClient.lastName} onChange={e => setNewClient({ ...newClient, lastName: e.target.value })} />
                  <TextField label="Email" variant="outlined" fullWidth required value={newClient.email} onChange={e => setNewClient({ ...newClient, email: e.target.value })} />
                  <TextField label="Phone" variant="outlined" fullWidth required value={newClient.phone} onChange={e => setNewClient({ ...newClient, phone: e.target.value })} />
                  <TextField label="Password" variant="outlined" fullWidth required value={newClient.password} onChange={e => setNewClient({ ...newClient, password: e.target.value })} />
                  <FormControl fullWidth required>
                    <InputLabel id="add-company-label">Company</InputLabel>
                    <Select
                      labelId="add-company-label"
                      value={newClient.company}
                      label="Company"
                      onChange={e => setNewClient({ ...newClient, company: e.target.value })}
                    >
                      {companies.map(company => (
                        <MenuItem key={company.id || company._id} value={company.id || company._id}>{company.name}</MenuItem>
                      ))}
                    </Select>
                  </FormControl>
                </form>
              </DialogContent>
              <DialogActions>
                <Button onClick={() => setShowAddModal(false)} color="secondary" variant="outlined" sx={{ borderColor: '#2563eb', color: '#1e40af', '&:hover': { borderColor: '#1e40af', background: '#eff6ff' } }}>Cancel</Button>
                <Button onClick={handleAdd} color="primary" variant="contained" type="submit">Add Client</Button>
              </DialogActions>
            </Dialog>
          )}

          {/* Edit Modal */}
          {showEditModal && (
            <Dialog open={showEditModal} onClose={() => setShowEditModal(false)} maxWidth="sm" fullWidth>
              <DialogTitle>Edit Client</DialogTitle>
              <DialogContent dividers>
                <form className="flex flex-col gap-4" onSubmit={handleEdit}>
                  <TextField label="First Name" variant="outlined" fullWidth required value={editClient.firstName} onChange={e => setEditClient({ ...editClient, firstName: e.target.value })} />
                  <TextField label="Last Name" variant="outlined" fullWidth required value={editClient.lastName} onChange={e => setEditClient({ ...editClient, lastName: e.target.value })} />
                  <TextField label="Email" variant="outlined" fullWidth required value={editClient.email} onChange={e => setEditClient({ ...editClient, email: e.target.value })} />
                  <TextField label="Phone" variant="outlined" fullWidth required value={editClient.phone} onChange={e => setEditClient({ ...editClient, phone: e.target.value })} />
                  <FormControl fullWidth required>
                    <InputLabel id="edit-company-label">Company</InputLabel>
                    <Select
                      labelId="edit-company-label"
                      value={editClient.company}
                      label="Company"
                      onChange={e => setEditClient({ ...editClient, company: e.target.value })}
                    >
                      {companies.map(company => (
                        <MenuItem key={company.id || company._id} value={company.id || company._id}>{company.name}</MenuItem>
                      ))}
                    </Select>
                  </FormControl>
                </form>
              </DialogContent>
              <DialogActions>
                <Button onClick={() => setShowEditModal(false)} color="secondary" variant="outlined" sx={{ borderColor: '#2563eb', color: '#1e40af', '&:hover': { borderColor: '#1e40af', background: '#eff6ff' } }}>Cancel</Button>
                <Button onClick={handleEdit} color="primary" variant="contained" type="submit">Update</Button>
              </DialogActions>
            </Dialog>
          )}

          {/* Delete Confirmation Modal */}
          {showDeleteModal && (
            <Dialog open={showDeleteModal} onClose={() => setShowDeleteModal(false)} maxWidth="sm" fullWidth>
              <DialogTitle>Delete Client</DialogTitle>
              <DialogContent dividers>
                <p className="mb-6">Are you sure you want to delete this client?</p>
              </DialogContent>
              <DialogActions>
                <Button onClick={() => setShowDeleteModal(false)} color="secondary" variant="outlined" sx={{ borderColor: '#2563eb', color: '#1e40af', '&:hover': { borderColor: '#1e40af', background: '#eff6ff' } }}>Cancel</Button>
                <Button onClick={handleDelete} color="primary" variant="contained" type="submit">Delete</Button>
              </DialogActions>
            </Dialog>
          )}
        </div>
      </div>
    </div>
  );
};

export default Clients; 