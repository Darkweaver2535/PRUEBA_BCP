# PRUEBA_BCP

## 1. Crear el proyecto
```bash
dotnet new webapi -n TestBCP
cd TestBCP
```

## 2. Instalar paquetes NuGet
```bash
dotnet add package Microsoft.EntityFrameworkCore.SqlServer
dotnet add package Microsoft.AspNetCore.Authentication.JwtBearer
dotnet add package Microsoft.EntityFrameworkCore.Tools
```

## 3. Estructura de carpetas y archivos:

```
TestBCP/
├── Controllers/
│   ├── AuthController.cs
│   └── UsersController.cs
├── Data/
│   └── AppDbContext.cs
├── Models/
│   └── User.cs
├── Services/
│   ├── IUserService.cs
│   ├── UserService.cs
│   ├── IAuthService.cs
│   └── AuthService.cs
├── SQL/
│   └── StoredProcedures.sql
├── Program.cs
├── appsettings.json
└── TestBCP.csproj
```

## **Program.cs** (reemplaza el contenido completo)
````csharp
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// Configurar Entity Framework
builder.Services.AddDbContext<AppDbContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));

// Configurar JWT
var jwtSettings = builder.Configuration.GetSection("JwtSettings");
var secretKey = jwtSettings["SecretKey"];

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = jwtSettings["Issuer"],
            ValidAudience = jwtSettings["Audience"],
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey))
        };
    });

builder.Services.AddControllers();
builder.Services.AddHttpClient();

// Servicios
builder.Services.AddScoped<IUserService, UserService>();
builder.Services.AddScoped<IAuthService, AuthService>();

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();

app.Run();
````

## **appsettings.json** (reemplaza el contenido completo)
````json
{
  "ConnectionStrings": {
    "DefaultConnection": "Server=localhost;Database=TestBCP;Trusted_Connection=true;TrustServerCertificate=true"
  },
  "JwtSettings": {
    "SecretKey": "MiClaveSecretaSuperSegura123456789",
    "Issuer": "TestBCP",
    "Audience": "TestBCP"
  },
  "Logging": {
    "LogLevel": {
      "Default": "Information",
      "Microsoft.AspNetCore": "Warning"
    }
  },
  "AllowedHosts": "*"
}
````

## **Models/User.cs** (crear carpeta Models y este archivo)
````csharp
using System.ComponentModel.DataAnnotations;

public class User
{
    public int Id { get; set; }
    
    [Required]
    public string Name { get; set; }
    
    [Required]
    [EmailAddress]
    public string Email { get; set; }
    
    [Required]
    public string Password { get; set; }
    
    public DateTime CreatedAt { get; set; } = DateTime.Now;
    public bool IsActive { get; set; } = true;
}

public class UserDto
{
    public int Id { get; set; }
    public string Name { get; set; }
    public string Email { get; set; }
    public DateTime CreatedAt { get; set; }
    public bool IsActive { get; set; }
}

public class CreateUserDto
{
    [Required]
    public string Name { get; set; }
    
    [Required]
    [EmailAddress]
    public string Email { get; set; }
    
    [Required]
    [MinLength(6)]
    public string Password { get; set; }
}

public class LoginDto
{
    [Required]
    public string Email { get; set; }
    
    [Required]
    public string Password { get; set; }
}

public class ApiResponse<T>
{
    public bool Success { get; set; }
    public string Message { get; set; }
    public T Data { get; set; }
    public List<string> Errors { get; set; } = new List<string>();
}
````

## **Data/AppDbContext.cs** (crear carpeta Data y este archivo)
````csharp
using Microsoft.EntityFrameworkCore;

public class AppDbContext : DbContext
{
    public AppDbContext(DbContextOptions<AppDbContext> options) : base(options) { }

    public DbSet<User> Users { get; set; }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<User>(entity =>
        {
            entity.HasKey(e => e.Id);
            entity.Property(e => e.Name).IsRequired().HasMaxLength(100);
            entity.Property(e => e.Email).IsRequired().HasMaxLength(100);
            entity.Property(e => e.Password).IsRequired().HasMaxLength(255);
            entity.HasIndex(e => e.Email).IsUnique();
        });
    }
}
````

## **Services/IUserService.cs** (crear carpeta Services y este archivo)
````csharp
public interface IUserService
{
    Task<ApiResponse<List<UserDto>>> GetAllUsersAsync();
    Task<ApiResponse<UserDto>> GetUserByIdAsync(int id);
    Task<ApiResponse<UserDto>> CreateUserAsync(CreateUserDto createUser);
    Task<ApiResponse<UserDto>> UpdateUserAsync(int id, CreateUserDto updateUser);
    Task<ApiResponse<bool>> DeleteUserAsync(int id);
}
````

## **Services/UserService.cs**
````csharp
using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;
using System.Security.Cryptography;
using System.Text;

public class UserService : IUserService
{
    private readonly AppDbContext _context;

    public UserService(AppDbContext context)
    {
        _context = context;
    }

    public async Task<ApiResponse<List<UserDto>>> GetAllUsersAsync()
    {
        try
        {
            // Usando stored procedure
            var users = await _context.Users
                .FromSqlRaw("EXEC GetAllActiveUsers")
                .Where(u => u.IsActive)
                .Select(u => new UserDto
                {
                    Id = u.Id,
                    Name = u.Name,
                    Email = u.Email,
                    CreatedAt = u.CreatedAt,
                    IsActive = u.IsActive
                })
                .ToListAsync();

            return new ApiResponse<List<UserDto>>
            {
                Success = true,
                Message = "Usuarios obtenidos exitosamente",
                Data = users
            };
        }
        catch (Exception ex)
        {
            return new ApiResponse<List<UserDto>>
            {
                Success = false,
                Message = "Error al obtener usuarios",
                Errors = new List<string> { ex.Message }
            };
        }
    }

    public async Task<ApiResponse<UserDto>> GetUserByIdAsync(int id)
    {
        try
        {
            var idParam = new SqlParameter("@Id", id);
            var user = await _context.Users
                .FromSqlRaw("EXEC GetUserById @Id", idParam)
                .FirstOrDefaultAsync();

            if (user == null)
            {
                return new ApiResponse<UserDto>
                {
                    Success = false,
                    Message = "Usuario no encontrado"
                };
            }

            var userDto = new UserDto
            {
                Id = user.Id,
                Name = user.Name,
                Email = user.Email,
                CreatedAt = user.CreatedAt,
                IsActive = user.IsActive
            };

            return new ApiResponse<UserDto>
            {
                Success = true,
                Message = "Usuario obtenido exitosamente",
                Data = userDto
            };
        }
        catch (Exception ex)
        {
            return new ApiResponse<UserDto>
            {
                Success = false,
                Message = "Error al obtener usuario",
                Errors = new List<string> { ex.Message }
            };
        }
    }

    public async Task<ApiResponse<UserDto>> CreateUserAsync(CreateUserDto createUser)
    {
        try
        {
            var hashedPassword = HashPassword(createUser.Password);
            
            var parameters = new[]
            {
                new SqlParameter("@Name", createUser.Name),
                new SqlParameter("@Email", createUser.Email),
                new SqlParameter("@Password", hashedPassword)
            };

            await _context.Database.ExecuteSqlRawAsync("EXEC CreateUser @Name, @Email, @Password", parameters);

            var user = await _context.Users.FirstOrDefaultAsync(u => u.Email == createUser.Email);
            
            var userDto = new UserDto
            {
                Id = user.Id,
                Name = user.Name,
                Email = user.Email,
                CreatedAt = user.CreatedAt,
                IsActive = user.IsActive
            };

            return new ApiResponse<UserDto>
            {
                Success = true,
                Message = "Usuario creado exitosamente",
                Data = userDto
            };
        }
        catch (Exception ex)
        {
            return new ApiResponse<UserDto>
            {
                Success = false,
                Message = "Error al crear usuario",
                Errors = new List<string> { ex.Message }
            };
        }
    }

    public async Task<ApiResponse<UserDto>> UpdateUserAsync(int id, CreateUserDto updateUser)
    {
        try
        {
            var hashedPassword = HashPassword(updateUser.Password);
            
            var parameters = new[]
            {
                new SqlParameter("@Id", id),
                new SqlParameter("@Name", updateUser.Name),
                new SqlParameter("@Email", updateUser.Email),
                new SqlParameter("@Password", hashedPassword)
            };

            await _context.Database.ExecuteSqlRawAsync("EXEC UpdateUser @Id, @Name, @Email, @Password", parameters);

            var user = await _context.Users.FindAsync(id);
            
            if (user == null)
            {
                return new ApiResponse<UserDto>
                {
                    Success = false,
                    Message = "Usuario no encontrado"
                };
            }

            var userDto = new UserDto
            {
                Id = user.Id,
                Name = user.Name,
                Email = user.Email,
                CreatedAt = user.CreatedAt,
                IsActive = user.IsActive
            };

            return new ApiResponse<UserDto>
            {
                Success = true,
                Message = "Usuario actualizado exitosamente",
                Data = userDto
            };
        }
        catch (Exception ex)
        {
            return new ApiResponse<UserDto>
            {
                Success = false,
                Message = "Error al actualizar usuario",
                Errors = new List<string> { ex.Message }
            };
        }
    }

    public async Task<ApiResponse<bool>> DeleteUserAsync(int id)
    {
        try
        {
            var idParam = new SqlParameter("@Id", id);
            await _context.Database.ExecuteSqlRawAsync("EXEC DeleteUser @Id", idParam);

            return new ApiResponse<bool>
            {
                Success = true,
                Message = "Usuario eliminado exitosamente",
                Data = true
            };
        }
        catch (Exception ex)
        {
            return new ApiResponse<bool>
            {
                Success = false,
                Message = "Error al eliminar usuario",
                Errors = new List<string> { ex.Message }
            };
        }
    }

    private string HashPassword(string password)
    {
        using (SHA256 sha256Hash = SHA256.Create())
        {
            byte[] bytes = sha256Hash.ComputeHash(Encoding.UTF8.GetBytes(password));
            StringBuilder builder = new StringBuilder();
            for (int i = 0; i < bytes.Length; i++)
            {
                builder.Append(bytes[i].ToString("x2"));
            }
            return builder.ToString();
        }
    }
}
````

## **Services/IAuthService.cs**
````csharp
public interface IAuthService
{
    Task<ApiResponse<string>> LoginAsync(LoginDto loginDto);
    Task<ApiResponse<object>> GetExternalDataAsync();
}
````

## **Services/AuthService.cs**
````csharp
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;

public class AuthService : IAuthService
{
    private readonly AppDbContext _context;
    private readonly IConfiguration _configuration;
    private readonly HttpClient _httpClient;

    public AuthService(AppDbContext context, IConfiguration configuration, HttpClient httpClient)
    {
        _context = context;
        _configuration = configuration;
        _httpClient = httpClient;
    }

    public async Task<ApiResponse<string>> LoginAsync(LoginDto loginDto)
    {
        try
        {
            var hashedPassword = HashPassword(loginDto.Password);
            var user = await _context.Users
                .FirstOrDefaultAsync(u => u.Email == loginDto.Email && u.Password == hashedPassword && u.IsActive);

            if (user == null)
            {
                return new ApiResponse<string>
                {
                    Success = false,
                    Message = "Credenciales inválidas"
                };
            }

            var token = GenerateJwtToken(user);

            return new ApiResponse<string>
            {
                Success = true,
                Message = "Login exitoso",
                Data = token
            };
        }
        catch (Exception ex)
        {
            return new ApiResponse<string>
            {
                Success = false,
                Message = "Error en el login",
                Errors = new List<string> { ex.Message }
            };
        }
    }

    public async Task<ApiResponse<object>> GetExternalDataAsync()
    {
        try
        {
            var response = await _httpClient.GetAsync("https://jsonplaceholder.typicode.com/posts/1");
            
            if (response.IsSuccessStatusCode)
            {
                var content = await response.Content.ReadAsStringAsync();
                return new ApiResponse<object>
                {
                    Success = true,
                    Message = "Datos externos obtenidos exitosamente",
                    Data = content
                };
            }

            return new ApiResponse<object>
            {
                Success = false,
                Message = "Error al obtener datos externos"
            };
        }
        catch (Exception ex)
        {
            return new ApiResponse<object>
            {
                Success = false,
                Message = "Error al consumir servicio externo",
                Errors = new List<string> { ex.Message }
            };
        }
    }

    private string GenerateJwtToken(User user)
    {
        var jwtSettings = _configuration.GetSection("JwtSettings");
        var secretKey = jwtSettings["SecretKey"];
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        var claims = new[]
        {
            new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
            new Claim(ClaimTypes.Email, user.Email),
            new Claim(ClaimTypes.Name, user.Name)
        };

        var token = new JwtSecurityToken(
            issuer: jwtSettings["Issuer"],
            audience: jwtSettings["Audience"],
            claims: claims,
            expires: DateTime.Now.AddHours(1),
            signingCredentials: creds
        );

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    private string HashPassword(string password)
    {
        using (SHA256 sha256Hash = SHA256.Create())
        {
            byte[] bytes = sha256Hash.ComputeHash(Encoding.UTF8.GetBytes(password));
            StringBuilder builder = new StringBuilder();
            for (int i = 0; i < bytes.Length; i++)
            {
                builder.Append(bytes[i].ToString("x2"));
            }
            return builder.ToString();
        }
    }
}
````

## **Controllers/AuthController.cs** (crear carpeta Controllers y este archivo)
````csharp
using Microsoft.AspNetCore.Mvc;

[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private readonly IAuthService _authService;

    public AuthController(IAuthService authService)
    {
        _authService = authService;
    }

    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginDto loginDto)
    {
        if (!ModelState.IsValid)
        {
            var errors = ModelState.Values.SelectMany(v => v.Errors).Select(e => e.ErrorMessage).ToList();
            return BadRequest(new ApiResponse<object>
            {
                Success = false,
                Message = "Datos de entrada inválidos",
                Errors = errors
            });
        }

        var result = await _authService.LoginAsync(loginDto);

        if (result.Success)
        {
            return Ok(result);
        }

        return Unauthorized(result);
    }

    [HttpGet("external-data")]
    public async Task<IActionResult> GetExternalData()
    {
        var result = await _authService.GetExternalDataAsync();

        if (result.Success)
        {
            return Ok(result);
        }

        return BadRequest(result);
    }
}
````

## **Controllers/UsersController.cs**
````csharp
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

[ApiController]
[Route("api/[controller]")]
[Authorize]
public class UsersController : ControllerBase
{
    private readonly IUserService _userService;

    public UsersController(IUserService userService)
    {
        _userService = userService;
    }

    [HttpGet]
    public async Task<IActionResult> GetAllUsers()
    {
        var result = await _userService.GetAllUsersAsync();

        if (result.Success)
        {
            return Ok(result);
        }

        return BadRequest(result);
    }

    [HttpGet("{id}")]
    public async Task<IActionResult> GetUser(int id)
    {
        var result = await _userService.GetUserByIdAsync(id);

        if (result.Success)
        {
            return Ok(result);
        }

        return NotFound(result);
    }

    [HttpPost]
    public async Task<IActionResult> CreateUser([FromBody] CreateUserDto createUser)
    {
        if (!ModelState.IsValid)
        {
            var errors = ModelState.Values.SelectMany(v => v.Errors).Select(e => e.ErrorMessage).ToList();
            return BadRequest(new ApiResponse<object>
            {
                Success = false,
                Message = "Datos de entrada inválidos",
                Errors = errors
            });
        }

        var result = await _userService.CreateUserAsync(createUser);

        if (result.Success)
        {
            return CreatedAtAction(nameof(GetUser), new { id = result.Data.Id }, result);
        }

        return BadRequest(result);
    }

    [HttpPut("{id}")]
    public async Task<IActionResult> UpdateUser(int id, [FromBody] CreateUserDto updateUser)
    {
        if (!ModelState.IsValid)
        {
            var errors = ModelState.Values.SelectMany(v => v.Errors).Select(e => e.ErrorMessage).ToList();
            return BadRequest(new ApiResponse<object>
            {
                Success = false,
                Message = "Datos de entrada inválidos",
                Errors = errors
            });
        }

        var result = await _userService.UpdateUserAsync(id, updateUser);

        if (result.Success)
        {
            return Ok(result);
        }

        return NotFound(result);
    }

    [HttpDelete("{id}")]
    public async Task<IActionResult> DeleteUser(int id)
    {
        var result = await _userService.DeleteUserAsync(id);

        if (result.Success)
        {
            return Ok(result);
        }

        return NotFound(result);
    }
}
````

## **SQL/StoredProcedures.sql** (crear carpeta SQL y este archivo)
```sql
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
```

## **Pasos finales:**

1. **Ejecuta el archivo SQL** en SQL Server Management Studio
2. **Cambia la cadena de conexión** en appsettings.json si es necesario
3. **Ejecuta el proyecto**: `dotnet run`
4. **Prueba con Postman** o cualquier herramienta:
   - Login: POST `http://localhost:5000/api/auth/login`
   - CRUD Users: `http://localhost:5000/api/users`

¡Listo! Cada archivo tiene su ubicación específica y extensión correcta.

¡Perfecto! En Mac puedes usar Azure Data Studio sin problemas. Te explico cómo:

## **1. Ejecutar SQL en Azure Data Studio:**

1. **Abre Azure Data Studio**
2. **Conecta a tu servidor SQL** (puede ser SQL Server local en Docker, Azure SQL, etc.)
3. **Crea una nueva consulta** (New Query)
4. **Copia y pega todo el contenido** del archivo `SQL/StoredProcedures.sql`
5. **Ejecuta todo el script** (Cmd+Shift+E o botón Run)

## **2. Si no tienes SQL Server en Mac, usa Docker:**

```bash
docker run -e ACCEPT_EULA=Y -e MSSQL_SA_PASSWORD=TuPassword123! -p 1433:1433 --name sqlserver -d mcr.microsoft.com/mssql/server:2022-latest
```

Luego conecta Azure Data Studio a:
- **Server**: `localhost,1433`
- **Username**: `sa`
- **Password**: `TuPassword123!`

## **3. Actualiza appsettings.json para Mac:**

````json
{
  "ConnectionStrings": {
    "DefaultConnection": "Server=localhost,1433;Database=TestBCP;User Id=sa;Password=TuPassword123!;TrustServerCertificate=true"
  },
  "JwtSettings": {
    "SecretKey": "MiClaveSecretaSuperSegura123456789",
    "Issuer": "TestBCP",
    "Audience": "TestBCP"
  },
  "Logging": {
    "LogLevel": {
      "Default": "Information",
      "Microsoft.AspNetCore": "Warning"
    }
  },
  "AllowedHosts": "*"
}
````

## **4. Comandos para Mac (todos iguales):**

```bash
# Crear proyecto
dotnet new webapi -n TestBCP
cd TestBCP

# Instalar paquetes
dotnet add package Microsoft.EntityFrameworkCore.SqlServer
dotnet add package Microsoft.AspNetCore.Authentication.JwtBearer
dotnet add package Microsoft.EntityFrameworkCore.Tools

# Ejecutar proyecto
dotnet run
```

## **5. Alternativa: Usar SQLite (más fácil para pruebas):**

Si quieres evitar Docker, puedes cambiar a SQLite:

**Instalar SQLite:**
```bash
dotnet add package Microsoft.EntityFrameworkCore.Sqlite
```

**Cambiar appsettings.json:**
````json
{
  "ConnectionStrings": {
    "DefaultConnection": "Data Source=testbcp.db"
  }
}
````

**Cambiar Program.cs** (línea del DbContext):
````csharp
// Cambiar esta línea:
// options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));

// Por esta:
options.UseSqlite(builder.Configuration.GetConnectionString("DefaultConnection")));
````

**Y crear la base con migraciones:**
```bash
dotnet ef migrations add InitialCreate
dotnet ef database update
```

## **6. Script SQL simplificado para SQLite:**

Si usas SQLite, crea este archivo **SQL/sqlite_setup.sql**:

```sql
-- Para SQLite (más simple)
CREATE TABLE Users (
    Id INTEGER PRIMARY KEY AUTOINCREMENT,
    Name TEXT NOT NULL,
    Email TEXT NOT NULL UNIQUE,
    Password TEXT NOT NULL,
    CreatedAt DATETIME DEFAULT CURRENT_TIMESTAMP,
    IsActive BOOLEAN DEFAULT 1
);

-- Insertar usuario de prueba
INSERT INTO Users (Name, Email, Password) 
VALUES ('Test User', 'test@test.com', 'e10adc3949ba59abbe56e057f20f883e4bb077a59e5d0e3b4f2c8a84ee47b0f1');
```

## **Recomendación para la prueba:**

**Opción 1 (SQL Server + Docker)**: Más profesional, usa stored procedures
¡Perfecto! Después de ejecutar el script SQL, sigues estos pasos:

## **6. Verificar que la base de datos se creó correctamente:**

En Azure Data Studio, ejecuta esta consulta para verificar:
```sql
USE TestBCP;
SELECT * FROM Users;
```

Deberías ver el usuario de prueba que se insertó.

## **7. Crear las migraciones de Entity Framework:**

Aunque ya creaste la base manualmente, necesitas sincronizar Entity Framework:

```bash
# Ir a la carpeta del proyecto
cd TestBCP

# Crear migración inicial
dotnet ef migrations add InitialCreate

# Aplicar migración (esto sincroniza EF con tu base existente)
dotnet ef database update
```

## **8. Ejecutar el proyecto:**

```bash
dotnet run
```

Deberías ver algo como:
```
info: Microsoft.Hosting.Lifetime[14]
      Now listening on: http://localhost:5167
info: Microsoft.Hosting.Lifetime[0]
      Application started. Press Ctrl+C to shut down.
```

## **9. Probar los endpoints:**

### **Primer endpoint - Login:**
```bash
curl -X POST http://localhost:5167/api/auth/login \
-H "Content-Type: application/json" \
-d '{
  "email": "test@test.com",
  "password": "123456"
}'
```

**Respuesta esperada:**
```json
{
  "success": true,
  "message": "Login exitoso",
  "data": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "errors": []
}
```

### **Copiar el token y probar CRUD:**
```bash
# Obtener usuarios (usar el token del login anterior)
curl -X GET http://localhost:5167/api/users \
-H "Authorization: Bearer TU_TOKEN_AQUI"

# Crear usuario
curl -X POST http://localhost:5167/api/users \
-H "Content-Type: application/json" \
-H "Authorization: Bearer TU_TOKEN_AQUI" \
-d '{
  "name": "Juan Pérez",
  "email": "juan@test.com",
  "password": "123456"
}'
```

### **Probar servicio externo:**
```bash
curl -X GET http://localhost:5167/api/auth/external-data
```

## **10. Usar Postman (más fácil):**

1. **Importa esta colección en Postman:**

```json
{
  "info": {
    "name": "TestBCP API"
  },
  "item": [
    {
      "name": "Login",
      "request": {
        "method": "POST",
        "header": [
          {
            "key": "Content-Type",
            "value": "application/json"
          }
        ],
        "body": {
          "mode": "raw",
          "raw": "{\n  \"email\": \"test@test.com\",\n  \"password\": \"123456\"\n}"
        },
        "url": {
          "raw": "http://localhost:5167/api/auth/login",
          "protocol": "http",
          "host": ["localhost"],
          "port": "5167",
          "path": ["api", "auth", "login"]
        }
      }
    },
    {
      "name": "Get Users",
      "request": {
        "method": "GET",
        "header": [
          {
            "key": "Authorization",
            "value": "Bearer {{token}}"
          }
        ],
        "url": {
          "raw": "http://localhost:5167/api/users",
          "protocol": "http",
          "host": ["localhost"],
          "port": "5167",
          "path": ["api", "users"]
        }
      }
    }
  ]
}
```

## **11. Si hay errores comunes:**

### **Error de conexión a base de datos:**
```bash
# Verificar que Docker está corriendo
docker ps

# Si no está, reiniciar el contenedor
docker start sqlserver
```

### **Error de puertos:**
El puerto puede cambiar. Revisa la consola donde ejecutaste `dotnet run` para ver el puerto correcto.

### **Error de migración:**
```bash
# Si hay problemas con migraciones
dotnet ef database drop --force
dotnet ef migrations remove
dotnet ef migrations add InitialCreate
dotnet ef database update
```

## **12. Resumen de endpoints para la prueba:**

- **POST** `/api/auth/login` - Login (no requiere token)
- **GET** `/api/auth/external-data` - Servicio externo (no requiere token)
- **GET** `/api/users` - Obtener usuarios (requiere token)
- **POST** `/api/users` - Crear usuario (requiere token)
- **PUT** `/api/users/{id}` - Actualizar usuario (requiere token)
- **DELETE** `/api/users/{id}` - Eliminar usuario (requiere token)

