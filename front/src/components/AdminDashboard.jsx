import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";

export default function AdminDashboard({ user, token }) {
  const navigate = useNavigate();

  const [users, setUsers] = useState([]);
  const [logs, setLogs] = useState([]);
  const [showLogs, setShowLogs] = useState(false);
  const [loading, setLoading] = useState(false);

  // Protection : accès réservé admin
  useEffect(() => {
    if (!user || user.role !== "admin") {
      navigate("/");
    }
  }, [user, navigate]);

  // Récupération des utilisateurs
  useEffect(() => { fetch("/api/admin/users", { headers: { Authorization: `Bearer ${token}`,
      },
    })
      .then((res) => res.json())
      .then((data) => setUsers(data.users || []))
      .catch((err) => console.error("Erreur fetch users :", err));
  }, [token]);

  // Bannir un utilisateur
  const bannirUser = async (id) => {
    const confirmDelete = window.confirm(
      "Supprimer cet utilisateur et ses notes ?"
    );
    if (!confirmDelete) return;

    try {
      setLoading(true);

      await fetch(`/api/admin/users/${id}`, {
        method: "DELETE",
        headers: {
          Authorization: `Bearer ${token}`,
        },
      });

      setUsers((prev) => prev.filter((u) => u.id !== id));
    } catch (err) {
      console.error("Erreur suppression :", err);
    } finally {
      setLoading(false);
    }
  };

  // Récupérer les logs
  const fetchLogs = async () => {
    try {
      const res = await fetch("/api/admin/logs", {
        headers: {
          Authorization: `Bearer ${token}`,
        },
      });

      const data = await res.json();
      setLogs(data.logs || []);
      setShowLogs(true);
    } catch (err) {
      console.error("Erreur logs :", err);
    }
  };

  return (
    <div>
      <h1>Panneau d'administration</h1>

      <table border="1">
        <thead>
          <tr>
            <th>ID</th>
            <th>Email</th>
            <th>Rôle</th>
            <th>Action</th>
          </tr>
        </thead>

        <tbody>
          {users.map((user) => (
            <tr key={user.id}>
              <td>{user.id}</td>
              <td>{user.email}</td>
              <td>{user.role}</td>
              <td>{user.bio}</td>
              <td>
                {u.id !== user.id && (
                  <button
                    onClick={() => bannirUser(u.id)}
                    disabled={loading}
                  >
                    Bannir
                  </button>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>

      <br />
      <button onClick={fetchLogs}>Voir l'historique</button>

      {showLogs && (
        <ul>
          {logs.length === 0 ? (
            <li>Aucune action enregistrée.</li>
          ) : (
            logs.map((log, index) => <li key={index}>{log}</li>)
          )}
        </ul>
      )}
    </div>
  );
}

