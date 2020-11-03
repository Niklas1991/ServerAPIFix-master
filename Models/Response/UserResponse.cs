using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace ServerAPI.Models.Response
{
	public class UserResponse
	{
		public string EmployeeId { get; set; }
		public string Username { get; set; }
		public string Email { get; set; }
		public string Role { get; set; }
	}
}
