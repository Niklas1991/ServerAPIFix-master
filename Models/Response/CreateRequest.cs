using System.ComponentModel.DataAnnotations;
using ServerAPI.Entities;

namespace ServerAPI.Models.Response
{
    public class CreateRequest
    {      
        [Required]
        public string UserName { get; set; }
        [Required]
        public int EmployeeId { get; set; }
        [Required]
        [EnumDataType(typeof(Role))]
        public string Role { get; set; }

        [Required]
        [EmailAddress]
        public string Email { get; set; }

        [Required]
        [MinLength(6)]
        public string Password { get; set; }
       
    }
}