import { useState } from 'react';
import { BrowserRouter as Router, Route, Routes, Navigate } from 'react-router-dom';
import Login from '../components/Login';
import ProtectedRoute from '../components/ProtectedRoute';
import HomePage from '../components/HomePage'; // Assume this is a protected home page component
import About from '../components/About';

const AppRouter = () => {
    const [isLoggedIn, setIsLoggedIn] = useState(sessionStorage.getItem('jwt') ? true : false);

    const handleLogin = () => setIsLoggedIn(true);
    const handleLogout = () => {
        sessionStorage.clear();
        setIsLoggedIn(false);
    };

    return (
        <Router>
            <Routes>
                <Route path="/login" element={isLoggedIn ? <Navigate to="/" /> : <Login onLogin={handleLogin} />} />

                <Route path="/" element={
                    <ProtectedRoute isLoggedIn={isLoggedIn}>
                        <HomePage onLogout={handleLogout} />

                    </ProtectedRoute>
                } />
                <Route path="/ab" element={
                    <ProtectedRoute isLoggedIn={isLoggedIn}>
                        <About />
                    </ProtectedRoute>
                } />
                {/* Add more routes as needed */}
            </Routes>
        </Router>
    );
};

export default AppRouter;
