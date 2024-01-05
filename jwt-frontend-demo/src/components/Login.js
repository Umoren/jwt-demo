import { useState } from 'react';
import api from '../utils/axios';
import { useNavigate } from 'react-router-dom';
import "../styles/Login.css"

const Login = ({ onLogin }) => {
    const [username, setUsername] = useState('');
    const [password, setPassword] = useState('');
    const [errorMessage, setErrorMessage] = useState('');
    const navigate = useNavigate();


    const handleLogin = async (event) => {
        event.preventDefault();
        try {
            const response = await api.post('/login', { username, password });
            sessionStorage.setItem('jwt', response.data.jwt);
            sessionStorage.setItem('refreshToken', response.data.refreshToken);
            onLogin();
            navigate('/');

            // const refreshResponse = await api.post('/token', { refreshToken: response.data.refreshToken });
            // sessionStorage.setItem('jwt', refreshResponse.data.jwt);
            // Redirect to a protected route or home page after successful login
        } catch (error) {
            setErrorMessage('Failed to login. Please check your credentials.');
        }
    };

    return (
        <div className="login-container">
            <form onSubmit={handleLogin} className="login-form">
                <input
                    type="text"
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                    placeholder="Username"
                />
                <input
                    type="password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder="Password"
                />
                <button type="submit">Login</button>
            </form>
            {errorMessage && <p className="error-message">{errorMessage}</p>}
        </div>
    );
};

export default Login;
