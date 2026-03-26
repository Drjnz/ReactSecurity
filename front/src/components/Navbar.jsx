import { Link } from "react-router-dom";

export default function Navbar({ user }) {
  return (
    <nav>
      <Link to="/">Accueil</Link>

      {/* Affichage uniquement si admin */}
      {user && user.role === "admin" && (
        <Link to="/admin">Panneau d'administration</Link>
      )}
    </nav>
  );
}
