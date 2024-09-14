namespace Identity.Models.ViewModels
{
    public class TwoFactorAuthenticationViewModel
    {
        public string Code { get; set; }
        public string? Token { get; set; }
        public string? QrCodeUrl { get; set; }
    }
}
