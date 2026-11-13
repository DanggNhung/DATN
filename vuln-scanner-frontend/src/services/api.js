import axios from 'axios';

// baseURL ưu tiên lấy từ biến môi trường VITE_API_URL (khi deploy production),
// fallback về '/api/v1' cho môi trường dev qua Vite proxy
const API_BASE_URL = import.meta.env.VITE_API_URL 
  ? `${import.meta.env.VITE_API_URL.replace(/\/+$/, '')}/api/v1`
  : '/api/v1';

const api = axios.create({
  baseURL: API_BASE_URL,
  timeout: 30000
});

// Gắn token JWT vào Header nếu có
api.interceptors.request.use((config) => {
  const token = localStorage.getItem('token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// Xử lý lỗi 401 tự động logout
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response && error.response.status === 401) {
      // Token hết hạn
      localStorage.removeItem('token');
      localStorage.removeItem('user');
    }
    return Promise.reject(error);
  }
);

export const authAPI = {
  register: (data) => api.post('/auth/register', data),
  login: (data) => api.post('/auth/login', data),
  getMe: () => api.get('/auth/me'),
  regenerateApiKey: () => api.post('/auth/api-key/regenerate')
};

export const scanAPI = {
  uploadFile: (formData) =>
    api.post('/scan/upload', formData, {
      headers: { 'Content-Type': 'multipart/form-data' }
    }),
  scanRaw: (data) => api.post('/scan/raw', data),
  getHistory: (page = 1, limit = 10) => api.get(`/scan/history?page=${page}&limit=${limit}`),
  getScanById: (id) => api.get(`/scan/${id}`),
  getPublicStats: () => api.get('/scan/public/stats')
};

export const adminAPI = {
  getUsers: (page = 1, search = '') => api.get(`/admin/users?page=${page}&search=${search}`),
  toggleUserStatus: (userId) => api.patch(`/admin/users/${userId}/status`),
  updateUserRole: (userId, role) => api.patch(`/admin/users/${userId}/role`, { role }),
  triggerCisaSync: () => api.post('/admin/cisa/sync'),
  getCisaStatus: () => api.get('/admin/cisa/status'),
  getOverview: () => api.get('/admin/overview')
};

export const dastAPI = {
  scan: (data) => api.post('/dast/scan', data),
  getHistory: (page = 1, limit = 10) => api.get(`/dast/history?page=${page}&limit=${limit}`),
  getById: (id) => api.get(`/dast/${id}`),
  getZapStatus: () => api.get('/dast/zap-status')
};

export const exploitDbAPI = {
  scanWebsite: (data) => api.post('/exploitdb/scan', data),
  search: (query, params = {}) => api.get('/exploitdb/search', { params: { q: query, ...params } }),
  getStatus: () => api.get('/exploitdb/status'),
  triggerSync: () => api.post('/exploitdb/sync')
};

export default api;
