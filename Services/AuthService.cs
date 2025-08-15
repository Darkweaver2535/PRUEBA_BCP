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