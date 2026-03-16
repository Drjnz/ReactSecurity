import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import axios from 'axios';

function Register() {
    
    const [email, setEmail] = useState('');
    const [password, setPassword] = useState('');
    const [error, setError] = useState(''); 
    const navigate = useNavigate();

   
    const handleSubmit = async (e) => {
        e.preventDefault();
        setError('');

        try {
            await axios.post('http://localhost:3000/api/auth/register', { email, password });
            navigate('/login');
        } catch (err) {
            setError(err.response?.data?.message || "Erreur lors de l'inscription (Le back-end est-il prêt ?)");
        }
    };

    return (
        <div>
            <h2>Inscription</h2>
            <form onSubmit={handleSubmit}>
                <input
                    type="text" placeholder="Email" value={email}
                    onChange={(e) => setEmail(e.target.value)} required
                />
                <br /><br />
                <input
                    type="password" placeholder="Mot de passe" value={password}
                    onChange={(e) => setPassword(e.target.value)} required
                />
                <br /><br />
                <button type="submit">S'inscrire</button>
            </form>
        </div>
    );
}


export default Register;