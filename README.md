## descargar de repositorio

git clone https://github.com/SergioValleGarma/CleanArquitectureSSO.git

# crear la base de datos DBSSO
# en la capa infrastructure

Add-Migration crearDBSSO   
Update-Database 

## credenciales
  "email": "admin@sistema.com",
  "password": "Admin123!",
  "nombre": "Administrador",
  "apellido": "Sistema"