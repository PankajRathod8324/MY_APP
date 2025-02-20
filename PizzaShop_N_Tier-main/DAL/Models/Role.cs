using System;
using System.Collections.Generic;

namespace DAL.Models;

public partial class Role
{
    public int RoleId { get; set; }

    public int CreatedBy { get; set; }

    public DateTime CreatedAt { get; set; }

    public int ModifiedBy { get; set; }

    public DateTime ModifiedAt { get; set; }

    public string? RoleName { get; set; }

    public virtual ICollection<RoleAndPermission> RoleAndPermissions { get; } = new List<RoleAndPermission>();

    public virtual ICollection<User> Users { get; } = new List<User>();
}
