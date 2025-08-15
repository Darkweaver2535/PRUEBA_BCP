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