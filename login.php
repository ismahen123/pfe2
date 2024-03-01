<?php
session_start(); // Démarrer la session

// Connexion à la base de données
$servername = "localhost";
$username = "root";
$password = "";
$dbname = "akwel_db";

try {
    $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
    // set the PDO error mode to exception
    $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch(PDOException $e) {
    echo "Erreur de connexion: " . $e->getMessage();
    exit;
}

// Inscription de l'utilisateur
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['signup'])) {
    $username = $_POST['username'];
    $familyname = $_POST['familyname'];
    $poste = $_POST['poste'];
    $email = $_POST['email'];
    $cin = $_POST['id'];
    $password = $_POST['pswd'];
    $confirmPassword = $_POST['confirm_password'];

    // Validation des données (à compléter selon vos besoins)

    // Vérification si l'email est déjà utilisé
    $query = "SELECT * FROM users WHERE email=:email";
    $stmt = $conn->prepare($query);
    $stmt->bindParam(':email', $email);
    $stmt->execute();
    if ($stmt->rowCount() > 0) {
        echo "Cet email est déjà utilisé.";
        exit;
    }

    // Hashage du mot de passe
    $hashed_password = password_hash($password, PASSWORD_DEFAULT);

    // Insertion des données dans la base de données
    $query = "INSERT INTO users (username, familyname, poste, email, CIN, password) VALUES (:username, :familyname, :poste, :email, :cin, :password)";
    $stmt = $conn->prepare($query);
    $stmt->bindParam(':username', $username);
    $stmt->bindParam(':familyname', $familyname);
    $stmt->bindParam(':poste', $poste);
    $stmt->bindParam(':email', $email);
    $stmt->bindParam(':cin', $cin);
    $stmt->bindParam(':password', $hashed_password);
    try {
        $stmt->execute();
        echo "Inscription réussie.";
    } catch(PDOException $e) {
        echo "Erreur lors de l'inscription: " . $e->getMessage();
        exit;
    }
}

// Connexion de l'utilisateur
if ($_SERVER['REQUEST_METHOD'] === 'POST' ) {
    $email = $_POST['email'];
    $password = $_POST['pswd'];

    // Récupération de l'utilisateur depuis la base de données
    $query = "SELECT * FROM users WHERE email=:email";
    $stmt = $conn->prepare($query);
    $stmt->bindParam(':email', $email);
    $stmt->execute();

    if ($stmt->rowCount() > 0) {
        $user = $stmt->fetch(PDO::FETCH_ASSOC);
        if (password_verify($password, $user['PASSWORD'])) {
            // Connexion réussie, stocker les informations de l'utilisateur dans la session
            $_SESSION['CIN'] = $user['CIN'];
            $_SESSION['username'] = $user['username'];
            // Autres informations à stocker dans la session si nécessaire
            echo "Connexion réussie.";
        } else {
            echo "Identifiants incorrects.";
            exit;
        }
    } else {
        echo "Identifiants incorrects.";
        exit;
    }
}

// Déconnexion de l'utilisateur
if (isset($_POST['logout'])) {
    // Détruire la session et rediriger vers la page de connexion
    session_destroy();
    header("Location: login.php");
    exit;
}

$conn = null;
?>
