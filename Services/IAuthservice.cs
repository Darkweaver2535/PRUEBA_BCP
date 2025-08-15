public interface IAuthService
{
    Task<ApiResponse<string>> LoginAsync(LoginDto loginDto);
    Task<ApiResponse<object>> GetExternalDataAsync();
}