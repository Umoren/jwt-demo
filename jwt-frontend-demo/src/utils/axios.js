import axios from 'axios';
axios.defaults.withCredentials = true;

const api = axios.create({
    baseURL: 'http://localhost:5000' // Your backend base URL
});


// Request interceptor to attach JWT
api.interceptors.request.use(config => {
    const token = sessionStorage.getItem('jwt');
    if (token) {
        config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
}, error => {
    return Promise.reject(error);
});

// Response interceptor to handle token refresh
api.interceptors.response.use(response => response, async error => {
    const originalRequest = error.config;
    if (!originalRequest._retryCount) originalRequest._retryCount = 0;
    if (error.response.status === 401 && originalRequest._retryCount < 2) { // Limit to 2 retries
        originalRequest._retryCount++;
        const refreshToken = sessionStorage.getItem('refreshToken');
        console.log("Retrieved refresh token:", refreshToken);

        if (!refreshToken) {
            return Promise.reject(new Error("No refresh token available"));
        }

        try {
            const response = await api.post('/token', { refreshToken });
            sessionStorage.setItem('jwt', response.data.jwt);
            return api(originalRequest);
        } catch (refreshError) {
            return Promise.reject(refreshError);
        }
    }
    return Promise.reject(error);
});


export default api;
