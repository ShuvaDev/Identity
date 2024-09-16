﻿using Microsoft.AspNetCore.Authorization;

namespace Identity.Authorize
{
    public class AdminWithMoreThan1000DaysRequirement : IAuthorizationRequirement
    {
        public int Days { get; set; }
        public AdminWithMoreThan1000DaysRequirement(int days)
        {
            Days = days;
        }
    }
}
