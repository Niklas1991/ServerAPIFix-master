using System.ComponentModel.DataAnnotations;

namespace ServerAPI.Models.Response
{
    public class RegisterRequest
    {    
        [Required]
        public string UserName { get; set; }
        
        [Required]         
        public int EmployeeId { get; set; }

        [Required]
        [EmailAddress]
        public string Email { get; set; }

        [Required]
        [MinLength(6)]
        public string Password { get; set; }
    }
}