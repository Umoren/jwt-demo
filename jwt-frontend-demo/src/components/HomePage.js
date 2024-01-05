import { useEffect, useState } from 'react';
// import { useNavigate } from 'react-router-dom';
import api from '../utils/axios'; // Ensure you import your configured Axios instance

const HomePage = ({ onLogout }) => {
    const [userData, setUserData] = useState(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState('');
    // const navigate = useNavigate();

    useEffect(() => {
        const fetchData = async () => {
            try {
                const response = await api.get('/protected');
                setUserData(response.data.userData);
                setLoading(false);
            } catch (err) {
                setError('Failed to fetch data. Please login again.');
                setLoading(false);
                // onLogout(); // Clear the session
                // navigate('/login'); // Redirect to login page
            }
        };

        fetchData();
    }, []);

    if (loading) return <p>Loading...</p>;
    if (error) return <p>{error}</p>;

    return (
        <div>
            <h1>Welcome to the Home Page!</h1>
            {userData && <p>User data: {JSON.stringify(userData)}</p>}
            <button onClick={onLogout}>Logout</button>
        </div>
    );
};

export default HomePage;
