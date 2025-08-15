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