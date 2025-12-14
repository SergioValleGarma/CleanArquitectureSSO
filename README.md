## descargar de repositorio

git clone https://github.com/SergioValleGarma/CleanArquitectureSSO.git

# actualiza tu cadena de coneccion a tu base de datos 

{
  "ConnectionStrings": {
    "DefaultConnection": "Server=DESKTOP-KSJLU0B\\SQLNET;Database=DBSSO;User Id=sa;Password=uni;TrustServerCertificate=true;"
  }

# crear la base de datos DBSSO
# en la capa infrastructure

Add-Migration crearDBSSO   
Update-Database 


# credenciales de acceso
  "email": "admin@sistema.com",
  "password": "Admin123!",
  "nombre": "Administrador",
  "apellido": "Sistema"
  
# dockerizar dentro de la carpeta SSO
docker-compose up --build