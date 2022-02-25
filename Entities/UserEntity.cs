namespace jwt_web_api.Entities;

public class UserEntity
{
    public string Username { get; set; } = string.Empty;

    public byte[] PasswordHash { get; set; }

    public byte[] PasswordSalt { get; set; }
}