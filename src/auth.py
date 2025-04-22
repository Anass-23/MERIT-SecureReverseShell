import os
import json
import time
import bcrypt

class AuthDB:
    """Class to handle user authentication and management."""
    
    def __init__(self, auth_file_path):
        """Initialize with the path to the auth file."""
        self.auth_file = auth_file_path
        os.makedirs(os.path.dirname(auth_file_path), exist_ok=True)
        self.init_user_store()
    
    def init_user_store(self):
        """Initialize the user store if it doesn't exist."""
        if not os.path.exists(self.auth_file):
            # Create default admin user if no users exist
            users = {
                "users": {
                    "admin": {
                        "password_hash": bcrypt.hashpw("secure_admin_pwd_MERIT2025".encode('utf-8'), bcrypt.gensalt()).decode('utf-8'),
                        "is_admin": True,
                        "created_at": time.strftime("%Y-%m-%d %H:%M:%S")
                    }
                }
            }
            with open(self.auth_file, 'w') as f:
                json.dump(users, f, indent=4)
            return "[*] Created default user store with admin account"
        
        # Make sure the file exists and is valid JSON
        try:
            with open(self.auth_file, 'r') as f:
                users = json.load(f)
            # Validate structure
            if "users" not in users:
                users["users"] = {}
                with open(self.auth_file, 'w') as f:
                    json.dump(users, f, indent=4)
        except (json.JSONDecodeError, FileNotFoundError):
            # If file is "corrupted" or missing, create a new one
            users = {"users": {
                "admin": {
                    "password_hash": bcrypt.hashpw("admin".encode('utf-8'), bcrypt.gensalt()).decode('utf-8'),
                    "is_admin": True,
                    "created_at": time.strftime("%Y-%m-%d %H:%M:%S")
                }
            }}
            with open(self.auth_file, 'w') as f:
                json.dump(users, f, indent=4)
            return "[!] User store was corrupted or missing. Created new file with default admin account"
        
        return True
    
    def get_users(self):
        """Get all users from the auth file."""
        try:
            with open(self.auth_file, 'r') as f:
                users = json.load(f)
            return users.get("users", {})
        except (FileNotFoundError, json.JSONDecodeError):
            self.init_user_store()
            return {"admin": {
                "password_hash": bcrypt.hashpw("admin".encode('utf-8'), bcrypt.gensalt()).decode('utf-8'),
                "is_admin": True,
                "created_at": time.strftime("%Y-%m-%d %H:%M:%S")
            }}
    
    def add_user(self, username, password, is_admin=False):
        """Add a new user to the auth file."""
        if not username or not password:
            return False, "Username and password are required"
        
        # Validate username (alphanumeric only)
        if not username.isalnum():
            return False, "Username must contain only letters and numbers"
        
        try:
            with open(self.auth_file, 'r') as f:
                data = json.load(f)
            
            users = data.get("users", {})
            
            if username in users:
                return False, f"User {username} already exists"
            
            # Add new user
            users[username] = {
                "password_hash": bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8'),
                "is_admin": is_admin,
                "created_at": time.strftime("%Y-%m-%d %H:%M:%S")
            }
            
            data["users"] = users
            
            with open(self.auth_file, 'w') as f:
                json.dump(data, f, indent=4)
            
            return True, f"User {username} added successfully"
        except Exception as e:
            return False, f"Error adding user: {e}"
    
    def delete_user(self, username, current_user=None):
        """Delete a user from the auth file. Only admin users can delete users."""
        try:
            with open(self.auth_file, 'r') as f:
                data = json.load(f)
            
            users = data.get("users", {})
            
            # Check if current_user is admin - MUST HAVE ADMIN PERMISSIONS
            if not current_user or current_user not in users:
                return False, "Permission denied: Admin authentication required"
                
            is_admin = users[current_user].get("is_admin", False)
            if not is_admin:
                return False, "Permission denied: Only admin users can delete accounts"
            
            # Prevent users from deleting themselves
            if current_user == username:
                return False, "Cannot delete your own account while logged in"
            
            # Make sure we don't delete the last admin user
            if username not in users:
                return False, f"User {username} not found"
            
            admin_count = sum(1 for user in users.values() if user.get("is_admin", False))
            
            if users[username].get("is_admin", False) and admin_count <= 1:
                return False, "Cannot delete the last admin user"
            
            # Delete user
            del users[username]
            data["users"] = users
            
            with open(self.auth_file, 'w') as f:
                json.dump(data, f, indent=4)
            
            return True, f"User {username} deleted successfully"
        except Exception as e:
            return False, f"Error deleting user: {e}"
    
    def verify_user(self, username, password):
        """Verify a user's credentials."""
        try:
            users = self.get_users()
            
            if username not in users:
                return False
            
            stored_hash = users[username]["password_hash"]
            return bcrypt.checkpw(password.encode('utf-8'), stored_hash.encode('utf-8'))
        except Exception as e:
            return False