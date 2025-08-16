-- Scripts SQL para crear la base de datos y stored procedures
-- Ejecutar estos comandos en SQL Server Management Studio

-- Crear la base de datos
CREATE DATABASE TestBCP;
GO

USE TestBCP;
GO

-- Crear la tabla Users
CREATE TABLE Users (
    Id INT IDENTITY(1,1) PRIMARY KEY,
    Name NVARCHAR(100) NOT NULL,
    Email NVARCHAR(100) NOT NULL UNIQUE,
    Password NVARCHAR(255) NOT NULL,
    CreatedAt DATETIME2 DEFAULT GETDATE(),
    IsActive BIT DEFAULT 1
);
GO

-- Stored Procedure para obtener todos los usuarios activos
CREATE PROCEDURE GetAllActiveUsers
AS
BEGIN
    SELECT Id, Name, Email, Password, CreatedAt, IsActive 
    FROM Users 
    WHERE IsActive = 1
    ORDER BY CreatedAt DESC
END
GO

-- Stored Procedure para obtener usuario por ID
CREATE PROCEDURE GetUserById
    @Id INT
AS
BEGIN
    SELECT Id, Name, Email, Password, CreatedAt, IsActive 
    FROM Users 
    WHERE Id = @Id AND IsActive = 1
END
GO

-- Stored Procedure para crear usuario
CREATE PROCEDURE CreateUser
    @Name NVARCHAR(100),
    @Email NVARCHAR(100),
    @Password NVARCHAR(255)
AS
BEGIN
    INSERT INTO Users (Name, Email, Password)
    VALUES (@Name, @Email, @Password)
END
GO

-- Stored Procedure para actualizar usuario
CREATE PROCEDURE UpdateUser
    @Id INT,
    @Name NVARCHAR(100),
    @Email NVARCHAR(100),
    @Password NVARCHAR(255)
AS
BEGIN
    UPDATE Users 
    SET Name = @Name, Email = @Email, Password = @Password
    WHERE Id = @Id
END
GO

-- Stored Procedure para eliminar usuario (soft delete)
CREATE PROCEDURE DeleteUser
    @Id INT
AS
BEGIN
    UPDATE Users 
    SET IsActive = 0
    WHERE Id = @Id
END
GO

-- Insertar un usuario de prueba (contraseña: "123456")
INSERT INTO Users (Name, Email, Password) 
VALUES ('Test User', 'test@test.com', 'e10adc3949ba59abbe56e057f20f883e4bb077a59e5d0e3b4f2c8a84ee47b0f1');
GO