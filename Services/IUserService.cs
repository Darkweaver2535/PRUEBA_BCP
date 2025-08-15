public interface IUserService
{
    Task<ApiResponse<List<UserDto>>> GetAllUsersAsync();
    Task<ApiResponse<UserDto>> GetUserByIdAsync(int id);
    Task<ApiResponse<UserDto>> CreateUserAsync(CreateUserDto createUser);
    Task<ApiResponse<UserDto>> UpdateUserAsync(int id, CreateUserDto updateUser);
    Task<ApiResponse<bool>> DeleteUserAsync(int id);
}