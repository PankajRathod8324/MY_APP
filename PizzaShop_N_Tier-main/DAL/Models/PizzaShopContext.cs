﻿using System;
using System.Collections.Generic;
using Microsoft.EntityFrameworkCore;

namespace DAL.Models;

public partial class PizzaShopContext : DbContext
{
    public PizzaShopContext()
    {
    }

    public PizzaShopContext(DbContextOptions<PizzaShopContext> options)
        : base(options)
    {
    }

    public virtual DbSet<City> Cities { get; set; }

    public virtual DbSet<CombineModifier> CombineModifiers { get; set; }

    public virtual DbSet<Country> Countries { get; set; }

    public virtual DbSet<Customer> Customers { get; set; }

    public virtual DbSet<CustomerTable> CustomerTables { get; set; }

    public virtual DbSet<Favourite> Favourites { get; set; }

    public virtual DbSet<MenuCategory> MenuCategories { get; set; }

    public virtual DbSet<MenuItem> MenuItems { get; set; }

    public virtual DbSet<MenuItemUnit> MenuItemUnits { get; set; }

    public virtual DbSet<MenuModifier> MenuModifiers { get; set; }

    public virtual DbSet<MenuModifierGroup> MenuModifierGroups { get; set; }

    public virtual DbSet<Order> Orders { get; set; }

    public virtual DbSet<OrderItem> OrderItems { get; set; }

    public virtual DbSet<OrderModifier> OrderModifiers { get; set; }

    public virtual DbSet<OrderTable> OrderTables { get; set; }

    public virtual DbSet<Permission> Permissions { get; set; }

    public virtual DbSet<Review> Reviews { get; set; }

    public virtual DbSet<Role> Roles { get; set; }

    public virtual DbSet<RoleAndPermission> RoleAndPermissions { get; set; }

    public virtual DbSet<Section> Sections { get; set; }

    public virtual DbSet<State> States { get; set; }

    public virtual DbSet<Table> Tables { get; set; }

    public virtual DbSet<Taxis> Taxes { get; set; }

    public virtual DbSet<Unit> Units { get; set; }

    public virtual DbSet<User> Users { get; set; }

    public virtual DbSet<WaitingList> WaitingLists { get; set; }

    protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
#warning To protect potentially sensitive information in your connection string, you should move it out of source code. You can avoid scaffolding the connection string by using the Name= syntax to read it from configuration - see https://go.microsoft.com/fwlink/?linkid=2131148. For more guidance on storing connection strings, see http://go.microsoft.com/fwlink/?LinkId=723263.
        => optionsBuilder.UseNpgsql("Host=localhost; Database=PizzaShop; Username=postgres;     password=tatva123 ");

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<City>(entity =>
        {
            entity.HasKey(e => e.CityId).HasName("cities_pkey");

            entity.ToTable("cities");

            entity.Property(e => e.CityId).HasColumnName("city_id");
            entity.Property(e => e.CityName)
                .HasMaxLength(100)
                .HasColumnName("city_name");
            entity.Property(e => e.CreatedAt)
                .HasDefaultValueSql("now()")
                .HasColumnType("timestamp without time zone")
                .HasColumnName("created_at");
            entity.Property(e => e.CreatedBy).HasColumnName("created_by");
            entity.Property(e => e.ModifiedAt)
                .HasDefaultValueSql("now()")
                .HasColumnType("timestamp without time zone")
                .HasColumnName("modified_at");
            entity.Property(e => e.ModifiedBy).HasColumnName("modified_by");
            entity.Property(e => e.StateId).HasColumnName("state_id");

            entity.HasOne(d => d.State).WithMany(p => p.Cities)
                .HasForeignKey(d => d.StateId)
                .OnDelete(DeleteBehavior.SetNull)
                .HasConstraintName("cities_state_id_fkey");
        });

        modelBuilder.Entity<CombineModifier>(entity =>
        {
            entity.HasKey(e => e.CombineModifierId).HasName("combine_modifier_pkey");

            entity.ToTable("combine_modifier");

            entity.Property(e => e.CombineModifierId).HasColumnName("combine_modifier_id");
            entity.Property(e => e.ModifierGroupId).HasColumnName("modifier_group_id");
            entity.Property(e => e.ModifierId).HasColumnName("modifier_id");

            entity.HasOne(d => d.ModifierGroup).WithMany(p => p.CombineModifiers)
                .HasForeignKey(d => d.ModifierGroupId)
                .OnDelete(DeleteBehavior.SetNull)
                .HasConstraintName("combine_modifier_modifier_group_id_fkey");

            entity.HasOne(d => d.Modifier).WithMany(p => p.CombineModifiers)
                .HasForeignKey(d => d.ModifierId)
                .OnDelete(DeleteBehavior.SetNull)
                .HasConstraintName("combine_modifier_modifier_id_fkey");
        });

        modelBuilder.Entity<Country>(entity =>
        {
            entity.HasKey(e => e.CountryId).HasName("countries_pkey");

            entity.ToTable("countries");

            entity.Property(e => e.CountryId).HasColumnName("country_id");
            entity.Property(e => e.CountryName)
                .HasMaxLength(100)
                .HasColumnName("country_name");
            entity.Property(e => e.CreatedAt)
                .HasDefaultValueSql("now()")
                .HasColumnType("timestamp without time zone")
                .HasColumnName("created_at");
            entity.Property(e => e.CreatedBy).HasColumnName("created_by");
            entity.Property(e => e.ModifiedAt)
                .HasDefaultValueSql("now()")
                .HasColumnType("timestamp without time zone")
                .HasColumnName("modified_at");
            entity.Property(e => e.ModifiedBy).HasColumnName("modified_by");
        });

        modelBuilder.Entity<Customer>(entity =>
        {
            entity.HasKey(e => e.CustomerId).HasName("customers_pkey");

            entity.ToTable("customers");

            entity.HasIndex(e => e.Email, "customers_email_key").IsUnique();

            entity.Property(e => e.CustomerId).HasColumnName("customer_id");
            entity.Property(e => e.CreatedAt)
                .HasDefaultValueSql("now()")
                .HasColumnType("timestamp without time zone")
                .HasColumnName("created_at");
            entity.Property(e => e.CreatedBy).HasColumnName("created_by");
            entity.Property(e => e.Email)
                .HasMaxLength(50)
                .HasColumnName("email");
            entity.Property(e => e.ModifiedAt)
                .HasDefaultValueSql("now()")
                .HasColumnType("timestamp without time zone")
                .HasColumnName("modified_at");
            entity.Property(e => e.ModifiedBy).HasColumnName("modified_by");
            entity.Property(e => e.Name)
                .HasMaxLength(100)
                .HasColumnName("name");
            entity.Property(e => e.Phone)
                .HasMaxLength(50)
                .HasColumnName("phone");
            entity.Property(e => e.TableId).HasColumnName("table_id");

            entity.HasOne(d => d.Table).WithMany(p => p.Customers)
                .HasForeignKey(d => d.TableId)
                .OnDelete(DeleteBehavior.SetNull)
                .HasConstraintName("customers_table_id_fkey");
        });

        modelBuilder.Entity<CustomerTable>(entity =>
        {
            entity.HasKey(e => e.CustomerTableId).HasName("customer_tables_pkey");

            entity.ToTable("customer_tables");

            entity.Property(e => e.CustomerTableId).HasColumnName("customer_table_id");
            entity.Property(e => e.CustomerId).HasColumnName("customer_id");
            entity.Property(e => e.TableId).HasColumnName("table_id");

            entity.HasOne(d => d.Customer).WithMany(p => p.CustomerTables)
                .HasForeignKey(d => d.CustomerId)
                .OnDelete(DeleteBehavior.SetNull)
                .HasConstraintName("customer_tables_customer_id_fkey");

            entity.HasOne(d => d.Table).WithMany(p => p.CustomerTables)
                .HasForeignKey(d => d.TableId)
                .OnDelete(DeleteBehavior.SetNull)
                .HasConstraintName("customer_tables_table_id_fkey");
        });

        modelBuilder.Entity<Favourite>(entity =>
        {
            entity.HasKey(e => e.FavouritesId).HasName("favourites_pkey");

            entity.ToTable("favourites");

            entity.Property(e => e.FavouritesId).HasColumnName("favourites_id");
            entity.Property(e => e.CreatedAt)
                .HasDefaultValueSql("now()")
                .HasColumnType("timestamp without time zone")
                .HasColumnName("created_at");
            entity.Property(e => e.CreatedBy).HasColumnName("created_by");
            entity.Property(e => e.ItemId).HasColumnName("item_id");
            entity.Property(e => e.ModifiedAt)
                .HasDefaultValueSql("now()")
                .HasColumnType("timestamp without time zone")
                .HasColumnName("modified_at");
            entity.Property(e => e.ModifiedBy).HasColumnName("modified_by");
            entity.Property(e => e.UserId).HasColumnName("user_id");

            entity.HasOne(d => d.Item).WithMany(p => p.Favourites)
                .HasForeignKey(d => d.ItemId)
                .OnDelete(DeleteBehavior.SetNull)
                .HasConstraintName("favourites_item_id_fkey");

            entity.HasOne(d => d.User).WithMany(p => p.Favourites)
                .HasForeignKey(d => d.UserId)
                .OnDelete(DeleteBehavior.SetNull)
                .HasConstraintName("favourites_user_id_fkey");
        });

        modelBuilder.Entity<MenuCategory>(entity =>
        {
            entity.HasKey(e => e.CategoryId).HasName("menu_categories_pkey");

            entity.ToTable("menu_categories");

            entity.Property(e => e.CategoryId).HasColumnName("category_id");
            entity.Property(e => e.CategoryDescription).HasColumnName("category_description");
            entity.Property(e => e.CategoryName)
                .HasMaxLength(100)
                .HasColumnName("category_name");
            entity.Property(e => e.CreatedAt)
                .HasDefaultValueSql("now()")
                .HasColumnType("timestamp without time zone")
                .HasColumnName("created_at");
            entity.Property(e => e.CreatedBy).HasColumnName("created_by");
            entity.Property(e => e.IsDeleted)
                .HasDefaultValueSql("false")
                .HasColumnName("is_deleted");
            entity.Property(e => e.ModifiedAt)
                .HasDefaultValueSql("now()")
                .HasColumnType("timestamp without time zone")
                .HasColumnName("modified_at");
            entity.Property(e => e.ModifiedBy).HasColumnName("modified_by");
        });

        modelBuilder.Entity<MenuItem>(entity =>
        {
            entity.HasKey(e => e.ItemId).HasName("menu_items_pkey");

            entity.ToTable("menu_items");

            entity.Property(e => e.ItemId).HasColumnName("item_id");
            entity.Property(e => e.CategoryId).HasColumnName("category_id");
            entity.Property(e => e.CategoryPhoto).HasColumnName("category_photo");
            entity.Property(e => e.CreatedAt)
                .HasDefaultValueSql("now()")
                .HasColumnType("timestamp without time zone")
                .HasColumnName("created_at");
            entity.Property(e => e.CreatedBy).HasColumnName("created_by");
            entity.Property(e => e.Description).HasColumnName("description");
            entity.Property(e => e.IsAvailable)
                .HasDefaultValueSql("true")
                .HasColumnName("is_available");
            entity.Property(e => e.IsFavourite)
                .HasDefaultValueSql("false")
                .HasColumnName("is_favourite");
            entity.Property(e => e.ItemName)
                .HasMaxLength(100)
                .HasColumnName("item_name");
            entity.Property(e => e.ItemType)
                .HasColumnType("character varying[]")
                .HasColumnName("item_type");
            entity.Property(e => e.ModifiedAt)
                .HasDefaultValueSql("now()")
                .HasColumnType("timestamp without time zone")
                .HasColumnName("modified_at");
            entity.Property(e => e.ModifiedBy).HasColumnName("modified_by");
            entity.Property(e => e.ModifierGroupId).HasColumnName("modifier_group_id");
            entity.Property(e => e.Quantity).HasColumnName("quantity");
            entity.Property(e => e.Rate)
                .HasPrecision(5, 2)
                .HasColumnName("rate");
            entity.Property(e => e.ShortCode).HasColumnName("short_code");
            entity.Property(e => e.TaxDefault)
                .HasDefaultValueSql("false")
                .HasColumnName("tax_default");
            entity.Property(e => e.TaxPercentage)
                .HasPrecision(10, 2)
                .HasColumnName("tax_percentage");
            entity.Property(e => e.UnitId).HasColumnName("unit_id");

            entity.HasOne(d => d.Category).WithMany(p => p.MenuItems)
                .HasForeignKey(d => d.CategoryId)
                .OnDelete(DeleteBehavior.SetNull)
                .HasConstraintName("menu_items_category_id_fkey");

            entity.HasOne(d => d.ModifierGroup).WithMany(p => p.MenuItems)
                .HasForeignKey(d => d.ModifierGroupId)
                .OnDelete(DeleteBehavior.SetNull)
                .HasConstraintName("menu_items_modifier_group_id_fkey");

            entity.HasOne(d => d.Unit).WithMany(p => p.MenuItems)
                .HasForeignKey(d => d.UnitId)
                .OnDelete(DeleteBehavior.SetNull)
                .HasConstraintName("menu_items_unit_id_fkey");
        });

        modelBuilder.Entity<MenuItemUnit>(entity =>
        {
            entity.HasKey(e => e.UnitId).HasName("menu_item_units_pkey");

            entity.ToTable("menu_item_units");

            entity.Property(e => e.UnitId).HasColumnName("unit_id");
            entity.Property(e => e.CreatedAt)
                .HasDefaultValueSql("now()")
                .HasColumnType("timestamp without time zone")
                .HasColumnName("created_at");
            entity.Property(e => e.CreatedBy).HasColumnName("created_by");
            entity.Property(e => e.ModifiedAt)
                .HasDefaultValueSql("now()")
                .HasColumnType("timestamp without time zone")
                .HasColumnName("modified_at");
            entity.Property(e => e.ModifiedBy).HasColumnName("modified_by");
            entity.Property(e => e.UnitName)
                .HasMaxLength(100)
                .HasColumnName("unit_name");
        });

        modelBuilder.Entity<MenuModifier>(entity =>
        {
            entity.HasKey(e => e.ModifierId).HasName("menu_modifiers_pkey");

            entity.ToTable("menu_modifiers");

            entity.Property(e => e.ModifierId).HasColumnName("modifier_id");
            entity.Property(e => e.CategoryId).HasColumnName("category_id");
            entity.Property(e => e.CreatedAt)
                .HasDefaultValueSql("now()")
                .HasColumnType("timestamp without time zone")
                .HasColumnName("created_at");
            entity.Property(e => e.CreatedBy).HasColumnName("created_by");
            entity.Property(e => e.IsDeleted)
                .HasDefaultValueSql("false")
                .HasColumnName("is_deleted");
            entity.Property(e => e.ModifiedAt)
                .HasDefaultValueSql("now()")
                .HasColumnType("timestamp without time zone")
                .HasColumnName("modified_at");
            entity.Property(e => e.ModifiedBy).HasColumnName("modified_by");
            entity.Property(e => e.ModifierDecription).HasColumnName("modifier_decription");
            entity.Property(e => e.ModifierGroupId).HasColumnName("modifier_group_id");
            entity.Property(e => e.ModifierName)
                .HasMaxLength(100)
                .HasColumnName("modifier_name");
            entity.Property(e => e.ModifierRate)
                .HasPrecision(5, 2)
                .HasColumnName("modifier_rate");
            entity.Property(e => e.Quantity).HasColumnName("quantity");
            entity.Property(e => e.UnitId).HasColumnName("unit_id");

            entity.HasOne(d => d.Category).WithMany(p => p.MenuModifiers)
                .HasForeignKey(d => d.CategoryId)
                .OnDelete(DeleteBehavior.SetNull)
                .HasConstraintName("menu_modifiers_category_id_fkey");

            entity.HasOne(d => d.ModifierGroup).WithMany(p => p.MenuModifiers)
                .HasForeignKey(d => d.ModifierGroupId)
                .OnDelete(DeleteBehavior.SetNull)
                .HasConstraintName("menu_modifiers_modifier_group_id_fkey");

            entity.HasOne(d => d.Unit).WithMany(p => p.MenuModifiers)
                .HasForeignKey(d => d.UnitId)
                .OnDelete(DeleteBehavior.SetNull)
                .HasConstraintName("menu_modifiers_unit_id_fkey");
        });

        modelBuilder.Entity<MenuModifierGroup>(entity =>
        {
            entity.HasKey(e => e.ModifierGroupId).HasName("menu_modifier_groups_pkey");

            entity.ToTable("menu_modifier_groups");

            entity.Property(e => e.ModifierGroupId).HasColumnName("modifier_group_id");
            entity.Property(e => e.CategoryId).HasColumnName("category_id");
            entity.Property(e => e.CreatedAt)
                .HasDefaultValueSql("now()")
                .HasColumnType("timestamp without time zone")
                .HasColumnName("created_at");
            entity.Property(e => e.CreatedBy).HasColumnName("created_by");
            entity.Property(e => e.IsDeleted)
                .HasDefaultValueSql("false")
                .HasColumnName("is_deleted");
            entity.Property(e => e.ModifiedAt)
                .HasDefaultValueSql("now()")
                .HasColumnType("timestamp without time zone")
                .HasColumnName("modified_at");
            entity.Property(e => e.ModifiedBy).HasColumnName("modified_by");
            entity.Property(e => e.ModifierGroupDecription).HasColumnName("modifier_group_decription");
            entity.Property(e => e.ModifierGroupName)
                .HasMaxLength(100)
                .HasColumnName("modifier_group_name");

            entity.HasOne(d => d.Category).WithMany(p => p.MenuModifierGroups)
                .HasForeignKey(d => d.CategoryId)
                .OnDelete(DeleteBehavior.SetNull)
                .HasConstraintName("menu_modifier_groups_category_id_fkey");
        });

        modelBuilder.Entity<Order>(entity =>
        {
            entity.HasKey(e => e.OrderId).HasName("orders_pkey");

            entity.ToTable("orders");

            entity.Property(e => e.OrderId).HasColumnName("order_id");
            entity.Property(e => e.Comment)
                .HasMaxLength(50)
                .HasColumnName("comment");
            entity.Property(e => e.CreatedAt)
                .HasDefaultValueSql("now()")
                .HasColumnType("timestamp without time zone")
                .HasColumnName("created_at");
            entity.Property(e => e.CreatedBy).HasColumnName("created_by");
            entity.Property(e => e.CustomerId).HasColumnName("customer_id");
            entity.Property(e => e.Date)
                .HasDefaultValueSql("now()")
                .HasColumnName("date");
            entity.Property(e => e.ModifiedAt)
                .HasDefaultValueSql("now()")
                .HasColumnType("timestamp without time zone")
                .HasColumnName("modified_at");
            entity.Property(e => e.ModifiedBy).HasColumnName("modified_by");
            entity.Property(e => e.NoOfPerson).HasColumnName("no_of_person");
            entity.Property(e => e.PaymentMode)
                .HasColumnType("character varying[]")
                .HasColumnName("payment_mode");
            entity.Property(e => e.ReviewId).HasColumnName("review_id");
            entity.Property(e => e.Status)
                .HasColumnType("character varying[]")
                .HasColumnName("status");
            entity.Property(e => e.SubTotal)
                .HasPrecision(10, 2)
                .HasColumnName("sub_total");
            entity.Property(e => e.TableId).HasColumnName("table_id");
            entity.Property(e => e.TaxId).HasColumnName("tax_id");
            entity.Property(e => e.TotalAmount)
                .HasPrecision(10, 2)
                .HasColumnName("total_amount");

            entity.HasOne(d => d.Customer).WithMany(p => p.Orders)
                .HasForeignKey(d => d.CustomerId)
                .OnDelete(DeleteBehavior.SetNull)
                .HasConstraintName("orders_customer_id_fkey");

            entity.HasOne(d => d.Review).WithMany(p => p.Orders)
                .HasForeignKey(d => d.ReviewId)
                .OnDelete(DeleteBehavior.SetNull)
                .HasConstraintName("orders_review_id_fkey");

            entity.HasOne(d => d.Table).WithMany(p => p.Orders)
                .HasForeignKey(d => d.TableId)
                .OnDelete(DeleteBehavior.SetNull)
                .HasConstraintName("orders_table_id_fkey");

            entity.HasOne(d => d.Tax).WithMany(p => p.Orders)
                .HasForeignKey(d => d.TaxId)
                .OnDelete(DeleteBehavior.SetNull)
                .HasConstraintName("orders_tax_id_fkey");
        });

        modelBuilder.Entity<OrderItem>(entity =>
        {
            entity.HasKey(e => e.OrderItemId).HasName("order_items_pkey");

            entity.ToTable("order_items");

            entity.Property(e => e.OrderItemId).HasColumnName("order_item_id");
            entity.Property(e => e.CreatedAt)
                .HasDefaultValueSql("now()")
                .HasColumnType("timestamp without time zone")
                .HasColumnName("created_at");
            entity.Property(e => e.CreatedBy).HasColumnName("created_by");
            entity.Property(e => e.Date)
                .HasDefaultValueSql("now()")
                .HasColumnName("date");
            entity.Property(e => e.ItemId).HasColumnName("item_id");
            entity.Property(e => e.ModifiedAt)
                .HasDefaultValueSql("now()")
                .HasColumnType("timestamp without time zone")
                .HasColumnName("modified_at");
            entity.Property(e => e.ModifiedBy).HasColumnName("modified_by");
            entity.Property(e => e.Quantity).HasColumnName("quantity");
            entity.Property(e => e.Rate)
                .HasPrecision(5, 2)
                .HasColumnName("rate");
            entity.Property(e => e.Readyitemquantity).HasColumnName("readyitemquantity");

            entity.HasOne(d => d.Item).WithMany(p => p.OrderItems)
                .HasForeignKey(d => d.ItemId)
                .OnDelete(DeleteBehavior.SetNull)
                .HasConstraintName("order_items_item_id_fkey");
        });

        modelBuilder.Entity<OrderModifier>(entity =>
        {
            entity.HasKey(e => e.OrderModifierId).HasName("order_modifiers_pkey");

            entity.ToTable("order_modifiers");

            entity.Property(e => e.OrderModifierId).HasColumnName("order_modifier_id");
            entity.Property(e => e.CreatedAt)
                .HasDefaultValueSql("now()")
                .HasColumnType("timestamp without time zone")
                .HasColumnName("created_at");
            entity.Property(e => e.CreatedBy).HasColumnName("created_by");
            entity.Property(e => e.Date)
                .HasDefaultValueSql("now()")
                .HasColumnName("date");
            entity.Property(e => e.ModifiedAt)
                .HasDefaultValueSql("now()")
                .HasColumnType("timestamp without time zone")
                .HasColumnName("modified_at");
            entity.Property(e => e.ModifiedBy).HasColumnName("modified_by");
            entity.Property(e => e.ModifierId).HasColumnName("modifier_id");
            entity.Property(e => e.Quantity).HasColumnName("quantity");
            entity.Property(e => e.Rate)
                .HasPrecision(5, 2)
                .HasColumnName("rate");

            entity.HasOne(d => d.Modifier).WithMany(p => p.OrderModifiers)
                .HasForeignKey(d => d.ModifierId)
                .OnDelete(DeleteBehavior.SetNull)
                .HasConstraintName("order_modifiers_modifier_id_fkey");
        });

        modelBuilder.Entity<OrderTable>(entity =>
        {
            entity.HasKey(e => e.OrderTableId).HasName("order_tables_pkey");

            entity.ToTable("order_tables");

            entity.Property(e => e.OrderTableId).HasColumnName("order_table_id");
            entity.Property(e => e.OrderId).HasColumnName("order_id");
            entity.Property(e => e.TableId).HasColumnName("table_id");

            entity.HasOne(d => d.Order).WithMany(p => p.OrderTables)
                .HasForeignKey(d => d.OrderId)
                .OnDelete(DeleteBehavior.SetNull)
                .HasConstraintName("order_tables_order_id_fkey");

            entity.HasOne(d => d.Table).WithMany(p => p.OrderTables)
                .HasForeignKey(d => d.TableId)
                .OnDelete(DeleteBehavior.SetNull)
                .HasConstraintName("order_tables_table_id_fkey");
        });

        modelBuilder.Entity<Permission>(entity =>
        {
            entity.HasKey(e => e.PermissionId).HasName("permissions_pkey");

            entity.ToTable("permissions");

            entity.Property(e => e.PermissionId).HasColumnName("permission_id");
            entity.Property(e => e.CanAddEdit)
                .HasDefaultValueSql("false")
                .HasColumnName("can_add_edit");
            entity.Property(e => e.CanDelete)
                .HasDefaultValueSql("false")
                .HasColumnName("can_delete");
            entity.Property(e => e.CanView)
                .HasDefaultValueSql("true")
                .HasColumnName("can_view");
            entity.Property(e => e.CreatedAt)
                .HasDefaultValueSql("now()")
                .HasColumnType("timestamp without time zone")
                .HasColumnName("created_at");
            entity.Property(e => e.CreatedBy).HasColumnName("created_by");
            entity.Property(e => e.ModifiedAt)
                .HasDefaultValueSql("now()")
                .HasColumnType("timestamp without time zone")
                .HasColumnName("modified_at");
            entity.Property(e => e.ModifiedBy).HasColumnName("modified_by");
            entity.Property(e => e.PermissionName)
                .HasMaxLength(50)
                .HasColumnName("permission_name");
        });

        modelBuilder.Entity<Review>(entity =>
        {
            entity.HasKey(e => e.ReviewId).HasName("reviews_pkey");

            entity.ToTable("reviews");

            entity.Property(e => e.ReviewId).HasColumnName("review_id");
            entity.Property(e => e.Ambience).HasColumnName("ambience");
            entity.Property(e => e.Comment).HasColumnName("comment");
            entity.Property(e => e.CreatedAt)
                .HasDefaultValueSql("now()")
                .HasColumnType("timestamp without time zone")
                .HasColumnName("created_at");
            entity.Property(e => e.CreatedBy).HasColumnName("created_by");
            entity.Property(e => e.Food).HasColumnName("food");
            entity.Property(e => e.ModifiedAt)
                .HasDefaultValueSql("now()")
                .HasColumnType("timestamp without time zone")
                .HasColumnName("modified_at");
            entity.Property(e => e.ModifiedBy).HasColumnName("modified_by");
            entity.Property(e => e.Rating).HasColumnName("rating");
            entity.Property(e => e.Service).HasColumnName("service");
        });

        modelBuilder.Entity<Role>(entity =>
        {
            entity.HasKey(e => e.RoleId).HasName("roles_pkey");

            entity.ToTable("roles");

            entity.Property(e => e.RoleId).HasColumnName("role_id");
            entity.Property(e => e.CreatedAt)
                .HasDefaultValueSql("now()")
                .HasColumnType("timestamp without time zone")
                .HasColumnName("created_at");
            entity.Property(e => e.CreatedBy).HasColumnName("created_by");
            entity.Property(e => e.ModifiedAt)
                .HasDefaultValueSql("now()")
                .HasColumnType("timestamp without time zone")
                .HasColumnName("modified_at");
            entity.Property(e => e.ModifiedBy).HasColumnName("modified_by");
            entity.Property(e => e.RoleName).HasColumnName("role_name");
        });

        modelBuilder.Entity<RoleAndPermission>(entity =>
        {
            entity.HasKey(e => new { e.RoleId, e.PermissionId }).HasName("role_and_permissions_pkey");

            entity.ToTable("role_and_permissions");

            entity.Property(e => e.RoleId).HasColumnName("role_id");
            entity.Property(e => e.PermissionId).HasColumnName("permission_id");
            entity.Property(e => e.CreatedAt)
                .HasDefaultValueSql("now()")
                .HasColumnType("timestamp without time zone")
                .HasColumnName("created_at");
            entity.Property(e => e.CreatedBy).HasColumnName("created_by");
            entity.Property(e => e.ModifiedAt)
                .HasDefaultValueSql("now()")
                .HasColumnType("timestamp without time zone")
                .HasColumnName("modified_at");
            entity.Property(e => e.ModifiedBy).HasColumnName("modified_by");

            entity.HasOne(d => d.Permission).WithMany(p => p.RoleAndPermissions)
                .HasForeignKey(d => d.PermissionId)
                .OnDelete(DeleteBehavior.SetNull)
                .HasConstraintName("role_and_permissions_permission_id_fkey");

            entity.HasOne(d => d.Role).WithMany(p => p.RoleAndPermissions)
                .HasForeignKey(d => d.RoleId)
                .OnDelete(DeleteBehavior.SetNull)
                .HasConstraintName("role_and_permissions_role_id_fkey");
        });

        modelBuilder.Entity<Section>(entity =>
        {
            entity.HasKey(e => e.SectionId).HasName("sections_pkey");

            entity.ToTable("sections");

            entity.Property(e => e.SectionId).HasColumnName("section_id");
            entity.Property(e => e.CreatedAt)
                .HasDefaultValueSql("now()")
                .HasColumnType("timestamp without time zone")
                .HasColumnName("created_at");
            entity.Property(e => e.CreatedBy).HasColumnName("created_by");
            entity.Property(e => e.IsDeleted)
                .HasDefaultValueSql("false")
                .HasColumnName("is_deleted");
            entity.Property(e => e.ModifiedAt)
                .HasDefaultValueSql("now()")
                .HasColumnType("timestamp without time zone")
                .HasColumnName("modified_at");
            entity.Property(e => e.ModifiedBy).HasColumnName("modified_by");
            entity.Property(e => e.SectionDecription).HasColumnName("section_decription");
            entity.Property(e => e.SectionName)
                .HasMaxLength(100)
                .HasColumnName("section_name");
        });

        modelBuilder.Entity<State>(entity =>
        {
            entity.HasKey(e => e.StateId).HasName("states_pkey");

            entity.ToTable("states");

            entity.Property(e => e.StateId).HasColumnName("state_id");
            entity.Property(e => e.CountryId).HasColumnName("country_id");
            entity.Property(e => e.CreatedAt)
                .HasDefaultValueSql("now()")
                .HasColumnType("timestamp without time zone")
                .HasColumnName("created_at");
            entity.Property(e => e.CreatedBy).HasColumnName("created_by");
            entity.Property(e => e.ModifiedAt)
                .HasDefaultValueSql("now()")
                .HasColumnType("timestamp without time zone")
                .HasColumnName("modified_at");
            entity.Property(e => e.ModifiedBy).HasColumnName("modified_by");
            entity.Property(e => e.StateName)
                .HasMaxLength(100)
                .HasColumnName("state_name");

            entity.HasOne(d => d.Country).WithMany(p => p.States)
                .HasForeignKey(d => d.CountryId)
                .OnDelete(DeleteBehavior.SetNull)
                .HasConstraintName("states_country_id_fkey");
        });

        modelBuilder.Entity<Table>(entity =>
        {
            entity.HasKey(e => e.TableId).HasName("tables_pkey");

            entity.ToTable("tables");

            entity.Property(e => e.TableId).HasColumnName("table_id");
            entity.Property(e => e.Capacity).HasColumnName("capacity");
            entity.Property(e => e.CreatedAt)
                .HasDefaultValueSql("now()")
                .HasColumnType("timestamp without time zone")
                .HasColumnName("created_at");
            entity.Property(e => e.CreatedBy).HasColumnName("created_by");
            entity.Property(e => e.ModifiedAt)
                .HasDefaultValueSql("now()")
                .HasColumnType("timestamp without time zone")
                .HasColumnName("modified_at");
            entity.Property(e => e.ModifiedBy).HasColumnName("modified_by");
            entity.Property(e => e.SectionId).HasColumnName("section_id");
            entity.Property(e => e.Status)
                .HasColumnType("character varying[]")
                .HasColumnName("status");
            entity.Property(e => e.TableName)
                .HasMaxLength(100)
                .HasColumnName("table_name");

            entity.HasOne(d => d.Section).WithMany(p => p.Tables)
                .HasForeignKey(d => d.SectionId)
                .OnDelete(DeleteBehavior.SetNull)
                .HasConstraintName("tables_section_id_fkey");
        });

        modelBuilder.Entity<Taxis>(entity =>
        {
            entity.HasKey(e => e.TaxId).HasName("taxes_pkey");

            entity.ToTable("taxes");

            entity.Property(e => e.TaxId).HasColumnName("tax_id");
            entity.Property(e => e.CreatedAt)
                .HasDefaultValueSql("now()")
                .HasColumnType("timestamp without time zone")
                .HasColumnName("created_at");
            entity.Property(e => e.CreatedBy).HasColumnName("created_by");
            entity.Property(e => e.IsDefault)
                .HasDefaultValueSql("false")
                .HasColumnName("is_default");
            entity.Property(e => e.IsEnabled)
                .HasDefaultValueSql("true")
                .HasColumnName("is_enabled");
            entity.Property(e => e.ModifiedAt)
                .HasDefaultValueSql("now()")
                .HasColumnType("timestamp without time zone")
                .HasColumnName("modified_at");
            entity.Property(e => e.ModifiedBy).HasColumnName("modified_by");
            entity.Property(e => e.TaxAmount)
                .HasPrecision(10, 2)
                .HasColumnName("tax_amount");
            entity.Property(e => e.TaxName)
                .HasMaxLength(100)
                .HasColumnName("tax_name");
            entity.Property(e => e.TaxType)
                .HasColumnType("character varying[]")
                .HasColumnName("tax_type");
        });

        modelBuilder.Entity<Unit>(entity =>
        {
            entity.HasKey(e => e.UnitId).HasName("units_pkey");

            entity.ToTable("units");

            entity.Property(e => e.UnitId).HasColumnName("unit_id");
            entity.Property(e => e.UnitName)
                .HasMaxLength(50)
                .HasColumnName("unit_name");
        });

        modelBuilder.Entity<User>(entity =>
        {
            entity.HasKey(e => e.UserId).HasName("users_pkey");

            entity.ToTable("users");

            entity.HasIndex(e => e.Email, "users_email_key").IsUnique();

            entity.HasIndex(e => e.Phone, "users_phone_key").IsUnique();

            entity.HasIndex(e => e.Username, "users_username_key").IsUnique();

            entity.Property(e => e.UserId).HasColumnName("user_id");
            entity.Property(e => e.Address).HasColumnName("address");
            entity.Property(e => e.CityId).HasColumnName("city_id");
            entity.Property(e => e.CountryId).HasColumnName("country_id");
            entity.Property(e => e.CreatedAt)
                .HasDefaultValueSql("now()")
                .HasColumnType("timestamp without time zone")
                .HasColumnName("created_at");
            entity.Property(e => e.CreatedBy).HasColumnName("created_by");
            entity.Property(e => e.Email)
                .HasMaxLength(50)
                .HasColumnName("email");
            entity.Property(e => e.FirstName)
                .HasMaxLength(50)
                .HasColumnName("first_name");
            entity.Property(e => e.LastLogin)
                .HasDefaultValueSql("now()")
                .HasColumnType("timestamp without time zone")
                .HasColumnName("last_login");
            entity.Property(e => e.LastName)
                .HasMaxLength(50)
                .HasColumnName("last_name");
            entity.Property(e => e.ModifiedAt)
                .HasDefaultValueSql("now()")
                .HasColumnType("timestamp without time zone")
                .HasColumnName("modified_at");
            entity.Property(e => e.ModifiedBy).HasColumnName("modified_by");
            entity.Property(e => e.Password).HasColumnName("password");
            entity.Property(e => e.Phone)
                .HasMaxLength(30)
                .HasColumnName("phone");
            entity.Property(e => e.ProfilePhoto).HasColumnName("profile_photo");
            entity.Property(e => e.ResetToken)
                .HasColumnType("character varying")
                .HasColumnName("reset_token");
            entity.Property(e => e.ResetTokenExpirytime).HasColumnName("reset_token_expirytime");
            entity.Property(e => e.RoleId).HasColumnName("role_id");
            entity.Property(e => e.StateId).HasColumnName("state_id");
            entity.Property(e => e.Username)
                .HasMaxLength(50)
                .HasColumnName("username");
            entity.Property(e => e.Zipcode)
                .HasMaxLength(30)
                .HasColumnName("zipcode");

            entity.HasOne(d => d.City).WithMany(p => p.Users)
                .HasForeignKey(d => d.CityId)
                .OnDelete(DeleteBehavior.SetNull)
                .HasConstraintName("users_city_id_fkey");

            entity.HasOne(d => d.Country).WithMany(p => p.Users)
                .HasForeignKey(d => d.CountryId)
                .OnDelete(DeleteBehavior.SetNull)
                .HasConstraintName("users_country_id_fkey");

            entity.HasOne(d => d.Role).WithMany(p => p.Users)
                .HasForeignKey(d => d.RoleId)
                .OnDelete(DeleteBehavior.Cascade)
                .HasConstraintName("users_role_id_fkey");

            entity.HasOne(d => d.State).WithMany(p => p.Users)
                .HasForeignKey(d => d.StateId)
                .OnDelete(DeleteBehavior.SetNull)
                .HasConstraintName("users_state_id_fkey");
        });

        modelBuilder.Entity<WaitingList>(entity =>
        {
            entity.HasKey(e => e.WaitingListId).HasName("waiting_list_pkey");

            entity.ToTable("waiting_list");

            entity.HasIndex(e => e.Email, "waiting_list_email_key").IsUnique();

            entity.HasIndex(e => e.Name, "waiting_list_name_key").IsUnique();

            entity.HasIndex(e => e.Phone, "waiting_list_phone_key").IsUnique();

            entity.Property(e => e.WaitingListId).HasColumnName("waiting_list_id");
            entity.Property(e => e.CreatedAt)
                .HasDefaultValueSql("now()")
                .HasColumnType("timestamp without time zone")
                .HasColumnName("created_at");
            entity.Property(e => e.CreatedBy).HasColumnName("created_by");
            entity.Property(e => e.CustomerId).HasColumnName("customer_id");
            entity.Property(e => e.Email)
                .HasMaxLength(50)
                .HasColumnName("email");
            entity.Property(e => e.FirstName)
                .HasMaxLength(50)
                .HasColumnName("first_name");
            entity.Property(e => e.LastName)
                .HasMaxLength(50)
                .HasColumnName("last_name");
            entity.Property(e => e.ModifiedAt)
                .HasDefaultValueSql("now()")
                .HasColumnType("timestamp without time zone")
                .HasColumnName("modified_at");
            entity.Property(e => e.ModifiedBy).HasColumnName("modified_by");
            entity.Property(e => e.Name)
                .HasMaxLength(50)
                .HasColumnName("name");
            entity.Property(e => e.NoOfPerson).HasColumnName("no_of_person");
            entity.Property(e => e.Phone)
                .HasMaxLength(30)
                .HasColumnName("phone");
            entity.Property(e => e.SectionId).HasColumnName("section_id");
            entity.Property(e => e.TableId).HasColumnName("table_id");
            entity.Property(e => e.WaitingTime)
                .HasColumnType("timestamp without time zone")
                .HasColumnName("waiting_time");

            entity.HasOne(d => d.Customer).WithMany(p => p.WaitingLists)
                .HasForeignKey(d => d.CustomerId)
                .OnDelete(DeleteBehavior.SetNull)
                .HasConstraintName("waiting_list_customer_id_fkey");

            entity.HasOne(d => d.Section).WithMany(p => p.WaitingLists)
                .HasForeignKey(d => d.SectionId)
                .OnDelete(DeleteBehavior.SetNull)
                .HasConstraintName("waiting_list_section_id_fkey");

            entity.HasOne(d => d.Table).WithMany(p => p.WaitingLists)
                .HasForeignKey(d => d.TableId)
                .OnDelete(DeleteBehavior.SetNull)
                .HasConstraintName("waiting_list_table_id_fkey");
        });

        OnModelCreatingPartial(modelBuilder);
    }

    partial void OnModelCreatingPartial(ModelBuilder modelBuilder);
}
