import { useState, useEffect } from 'react';
import axios from 'axios';
import { useNavigate } from 'react-router-dom';

function Dashboard() {
    const [notes, setNotes] = useState([]);
    const [newNote, setNewNote] = useState('');
    const navigate = useNavigate();

    // On récupère l'utilisateur "connecté" depuis le localStorage
    const user = JSON.parse(localStorage.getItem('user')) || { id: 1, role: 'user' };
    const token = localStorage.getItem('token');

    useEffect(() => {
        fetchNotes();
    }, []);

    const fetchNotes = async () => {
        try {
            const res = await axios.get('http://localhost:3000/api/notes', {
                headers: { Authorization: `Bearer ${token}` }
            });
            setNotes(res.data);
        } catch (err) {
            console.error("Erreur lors de la récupération des notes");
        }
    };

    const handleAddNote = async (e) => {
        e.preventDefault();
        try {
            await axios.post('http://localhost:3000/api/notes', {
                content: newNote,
                authorId: user.id
            }, {
                headers: { Authorization: `Bearer ${token}` }
            });
            setNewNote('');
            fetchNotes();
        } catch (err) {
            alert("Erreur lors de l'ajout");
        }
    };

    const handleDelete = async (noteId) => {
        try {
            await axios.delete(`http://localhost:3000/api/notes/${noteId}`, {
                headers: { Authorization: `Bearer ${token}` }
            });
            fetchNotes();
        } catch (err) {
            alert("Erreur lors de la suppression");
        }
    };

    const handleLogout = () => {
        localStorage.clear();
        navigate('/login');
    };

    return (
        <div>
            <button onClick={handleLogout}>Déconnexion</button>
            <h2>Tableau de bord de {user.email || 'Anonyme'}</h2>

            <form onSubmit={handleAddNote} style={{ marginBottom: '20px' }}>
                <textarea
                    value={newNote}
                    onChange={(e) => setNewNote(e.target.value)}
                    placeholder="Écrire une nouvelle note (accepte le HTML pour le TP !)"
                    rows="4" cols="50" required
                />
                <br />
                <button type="submit">Ajouter la note</button>
            </form>

            <div>
                {notes.map(note => (
                    <div key={note.id} style={{ border: '1px solid gray', margin: '10px 0', padding: '10px' }}>
                        <p dangerouslySetInnerHTML={{ __html: note.content }}></p>
                        <small>Auteur ID : {note.authorId}</small>
                        <br />

                        {user.role === 'admin' && (
                            <button onClick={() => handleDelete(note.id)} style={{ color: 'red', marginTop: '10px' }}>
                                Supprimer (Admin)
                            </button>
                        )}
                    </div>
                ))}
            </div>
        </div>
    );
}

export default Dashboard;