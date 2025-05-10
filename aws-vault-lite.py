#!/usr/bin/env python3
import os
import json
import tkinter as tk
from tkinter import messagebox
import customtkinter as ctk
import boto3
from botocore.exceptions import ClientError

# Set appearance mode and default color theme
ctk.set_appearance_mode("System")  # Modes: "System" (standard), "Dark", "Light"
ctk.set_default_color_theme("blue")  # Themes: "blue" (standard), "green", "dark-blue"

# Constants
SECRET_PATH = "/aws-vault-lite/vault"
DEFAULT_SECRET_STRUCTURE = {}

class PasswordEntry(ctk.CTkFrame):
    """Custom widget for password fields with show/hide functionality"""
    def __init__(self, master, placeholder="", **kwargs):
        super().__init__(master, **kwargs)
        self.grid_columnconfigure(0, weight=1)
        
        self.show_password = False
        self.value_var = ctk.StringVar()
        
        self.entry = ctk.CTkEntry(self, placeholder_text=placeholder, show="•", textvariable=self.value_var)
        self.entry.grid(row=0, column=0, sticky="ew", padx=(0, 5))
        
        self.toggle_btn = ctk.CTkButton(self, text="Show", width=60, 
                                        command=self.toggle_show_password)
        self.toggle_btn.grid(row=0, column=1)
    
    def toggle_show_password(self):
        self.show_password = not self.show_password
        self.entry.configure(show="" if self.show_password else "•")
        self.toggle_btn.configure(text="Hide" if self.show_password else "Show")
    
    def get(self):
        return self.value_var.get()
    
    def set(self, value):
        self.value_var.set(value)


class AttributeRow(ctk.CTkFrame):
    """Frame for a single attribute key-value pair"""
    def __init__(self, master, key="", value="", is_password=False, on_delete=None, **kwargs):
        super().__init__(master, **kwargs)
        self.grid_columnconfigure(1, weight=1)
        
        # Key entry
        self.key_var = ctk.StringVar(value=key)
        self.key_entry = ctk.CTkEntry(self, textvariable=self.key_var, width=120)
        self.key_entry.grid(row=0, column=0, padx=(0, 10), pady=5)
        
        # Value entry (regular or password)
        self.is_password = is_password
        if is_password:
            self.value_widget = PasswordEntry(self)
            self.value_widget.set(value)
        else:
            self.value_var = ctk.StringVar(value=value)
            self.value_widget = ctk.CTkEntry(self, textvariable=self.value_var)
        
        self.value_widget.grid(row=0, column=1, sticky="ew", pady=5)
        
        # Password toggle
        self.is_password_var = ctk.BooleanVar(value=is_password)
        self.password_toggle = ctk.CTkCheckBox(self, text="🔒", variable=self.is_password_var, 
                                              onvalue=True, offvalue=False, width=30,
                                              command=self.toggle_password_field)
        self.password_toggle.grid(row=0, column=2, padx=5, pady=5)
        
        # Delete button
        if on_delete:
            self.delete_btn = ctk.CTkButton(self, text="X", width=30, fg_color="transparent", 
                                           command=on_delete)
            self.delete_btn.grid(row=0, column=3, padx=(5, 0), pady=5)
    
    def toggle_password_field(self):
        is_password = self.is_password_var.get()
        current_value = self.get_value()
        
        # Remove current widget
        self.value_widget.grid_forget()
        
        # Create new widget based on state
        if is_password:
            self.value_widget = PasswordEntry(self)
            self.value_widget.set(current_value)
        else:
            self.value_var = ctk.StringVar(value=current_value)
            self.value_widget = ctk.CTkEntry(self, textvariable=self.value_var)
        
        self.value_widget.grid(row=0, column=1, sticky="ew", pady=5)
        self.is_password = is_password
    
    def get_key(self):
        return self.key_var.get()
    
    def get_value(self):
        if self.is_password:
            return self.value_widget.get()
        else:
            return self.value_var.get()
    
    def get_is_password(self):
        return self.is_password_var.get()


class AWSVaultLite(ctk.CTk):
    def __init__(self):
        super().__init__()
        
        # Configure window
        self.title("AWS Vault Lite")
        self.geometry("900x600")
        self.minsize(800, 500)
        
        # Initialize AWS client
        self.init_aws_client()
        
        # Setup UI
        self.setup_ui()
        
        # Load secrets
        self.load_secrets()
    
    def init_aws_client(self):
        """Initialize AWS Secrets Manager client using environment variables"""
        # Get AWS credentials from environment variables
        aws_access_key = os.environ.get('AWS_ACCESS_KEY_ID')
        aws_secret_key = os.environ.get('AWS_SECRET_ACCESS_KEY')
        aws_session_token = os.environ.get('AWS_SESSION_TOKEN')
        
        if not aws_access_key or not aws_secret_key:
            messagebox.showerror("AWS Credentials Missing", 
                                "AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY environment variables must be set.")
            self.quit()
            return
        
        # Create session with credentials
        session_kwargs = {
            'aws_access_key_id': aws_access_key,
            'aws_secret_access_key': aws_secret_key
        }
        
        if aws_session_token:
            session_kwargs['aws_session_token'] = aws_session_token
        
        try:
            self.session = boto3.session.Session(**session_kwargs)
            # Use us-east-1 as default region
            self.secrets_client = self.session.client('secretsmanager', region_name='us-east-1')
        except Exception as e:
            messagebox.showerror("AWS Client Error", f"Failed to initialize AWS client: {str(e)}")
            self.quit()
    
    def setup_ui(self):
        """Set up the main UI components"""
        # Configure grid
        self.grid_columnconfigure(0, weight=0)  # Secret list (fixed width)
        self.grid_columnconfigure(1, weight=1)  # Secret details (expandable)
        self.grid_rowconfigure(0, weight=1)     # Main content area
        self.grid_rowconfigure(1, weight=0)     # Bottom buttons
        
        # Left panel - Secret list
        self.setup_secret_list()
        
        # Right panel - Secret details
        self.setup_secret_details()
        
        # Bottom buttons
        self.setup_bottom_buttons()
    
    def setup_secret_list(self):
        """Set up the left panel with the list of secrets"""
        # Frame for secret list
        self.secret_list_frame = ctk.CTkFrame(self)
        self.secret_list_frame.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")
        
        # Label
        self.secret_list_label = ctk.CTkLabel(self.secret_list_frame, text="Secret List", 
                                             font=ctk.CTkFont(size=16, weight="bold"))
        self.secret_list_label.pack(pady=(10, 5), padx=10)
        
        # Scrollable frame for secrets
        self.secret_list_container = ctk.CTkScrollableFrame(self.secret_list_frame)
        self.secret_list_container.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Will be populated with secret buttons when loaded
        self.secret_buttons = []
    
    def setup_secret_details(self):
        """Set up the right panel with secret details"""
        # Frame for secret details
        self.secret_details_frame = ctk.CTkFrame(self)
        self.secret_details_frame.grid(row=0, column=1, padx=10, pady=10, sticky="nsew")
        self.secret_details_frame.grid_columnconfigure(0, weight=1)
        self.secret_details_frame.grid_rowconfigure(2, weight=1)  # Attributes area expands
        
        # Secret name
        self.name_frame = ctk.CTkFrame(self.secret_details_frame)
        self.name_frame.grid(row=0, column=0, padx=10, pady=(10, 5), sticky="ew")
        self.name_frame.grid_columnconfigure(1, weight=1)
        
        self.name_label = ctk.CTkLabel(self.name_frame, text="Secret Name*:", 
                                      font=ctk.CTkFont(weight="bold"))
        self.name_label.grid(row=0, column=0, padx=5, pady=5)
        
        self.name_var = ctk.StringVar()
        self.name_entry = ctk.CTkEntry(self.name_frame, textvariable=self.name_var)
        self.name_entry.grid(row=0, column=1, padx=5, pady=5, sticky="ew")
        
        # Attributes label
        self.attr_label = ctk.CTkLabel(self.secret_details_frame, text="Attributes:", 
                                      font=ctk.CTkFont(weight="bold"))
        self.attr_label.grid(row=1, column=0, padx=15, pady=(10, 5), sticky="w")
        
        # Scrollable frame for attributes
        self.attributes_container = ctk.CTkScrollableFrame(self.secret_details_frame)
        self.attributes_container.grid(row=2, column=0, padx=10, pady=5, sticky="nsew")
        self.attributes_container.grid_columnconfigure(0, weight=1)
        
        # Add attribute button
        self.add_attr_btn = ctk.CTkButton(self.secret_details_frame, text="+ Add Attribute", 
                                         command=self.add_attribute_row)
        self.add_attr_btn.grid(row=3, column=0, padx=10, pady=10, sticky="w")
        
        # Current attributes
        self.attribute_rows = []
    
    def setup_bottom_buttons(self):
        """Set up the bottom buttons"""
        # Bottom button frame
        self.bottom_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.bottom_frame.grid(row=1, column=0, columnspan=2, padx=10, pady=10, sticky="ew")
        
        # Add Secret button
        self.add_secret_btn = ctk.CTkButton(self.bottom_frame, text="+ Add Secret", 
                                           command=self.new_secret)
        self.add_secret_btn.pack(side="left", padx=10)
        
        # Save button
        self.save_btn = ctk.CTkButton(self.bottom_frame, text="Save", 
                                     command=self.save_current_secret)
        self.save_btn.pack(side="left", padx=10)
        
        # Delete button
        self.delete_btn = ctk.CTkButton(self.bottom_frame, text="Delete Secret", 
                                       fg_color="#d32f2f", hover_color="#b71c1c",
                                       command=self.delete_current_secret)
        self.delete_btn.pack(side="right", padx=10)
    
    def load_secrets(self):
        """Load secrets from AWS Secrets Manager"""
        try:
            response = self.secrets_client.get_secret_value(SecretId=SECRET_PATH)
            self.secrets_data = json.loads(response['SecretString'])
            self.populate_secret_list()
        except ClientError as e:
            if e.response['Error']['Code'] == 'ResourceNotFoundException':
                self.prompt_create_secret()
            else:
                messagebox.showerror("AWS Error", f"Failed to load secrets: {str(e)}")
    
    def prompt_create_secret(self):
        """Prompt user to create the secret if it doesn't exist"""
        response = messagebox.askyesno(
            "Secret Not Found", 
            f"The secret '{SECRET_PATH}' does not exist. Would you like to create it?"
        )
        
        if response:
            try:
                self.secrets_client.create_secret(
                    Name=SECRET_PATH,
                    SecretString=json.dumps(DEFAULT_SECRET_STRUCTURE)
                )
                messagebox.showinfo("Success", f"Secret '{SECRET_PATH}' created successfully.")
                self.secrets_data = DEFAULT_SECRET_STRUCTURE
            except Exception as e:
                messagebox.showerror("Error", f"Failed to create secret: {str(e)}")
                self.quit()
        else:
            messagebox.showinfo("Exiting", "Cannot proceed without creating the secret.")
            self.quit()
    
    def populate_secret_list(self):
        """Populate the secret list with buttons for each secret"""
        # Clear existing buttons
        for button in self.secret_buttons:
            button.destroy()
        self.secret_buttons = []
        
        # Add a button for each secret
        for secret_name in self.secrets_data.keys():
            btn = ctk.CTkButton(
                self.secret_list_container, 
                text=secret_name,
                anchor="w",
                command=lambda name=secret_name: self.load_secret_details(name)
            )
            btn.pack(fill="x", padx=5, pady=2)
            self.secret_buttons.append(btn)
        
        # If there are secrets, load the first one
        if self.secret_buttons:
            self.load_secret_details(next(iter(self.secrets_data)))
        else:
            self.clear_secret_details()
            self.name_entry.configure(state="normal")
    
    def load_secret_details(self, secret_name):
        """Load and display details for the selected secret"""
        if secret_name not in self.secrets_data:
            return
        
        # Set the secret name
        self.name_var.set(secret_name)
        self.name_entry.configure(state="disabled")  # Can't change existing secret name
        
        # Clear existing attribute rows
        self.clear_attributes()
        
        # Add attribute rows for each key-value pair
        secret_data = self.secrets_data[secret_name]
        for key, value in secret_data.items():
            # Determine if this is likely a password field
            is_password = any(pwd_key in key.lower() for pwd_key in ['password', 'secret', 'token', 'key'])
            self.add_attribute_row(key, value, is_password)
    
    def clear_secret_details(self):
        """Clear the secret details panel"""
        self.name_var.set("")
        self.clear_attributes()
    
    def clear_attributes(self):
        """Clear all attribute rows"""
        for row in self.attribute_rows:
            row.destroy()
        self.attribute_rows = []
    
    def add_attribute_row(self, key="", value="", is_password=False):
        """Add a new attribute row to the attributes container"""
        row = AttributeRow(
            self.attributes_container,
            key=key,
            value=value,
            is_password=is_password,
            on_delete=lambda r=None: self.delete_attribute_row(r)
        )
        row.pack(fill="x", padx=5, pady=2)
        self.attribute_rows.append(row)
        return row
    
    def delete_attribute_row(self, row):
        """Delete an attribute row"""
        if row in self.attribute_rows:
            self.attribute_rows.remove(row)
            row.destroy()
    
    def new_secret(self):
        """Start creating a new secret"""
        self.clear_secret_details()
        self.name_entry.configure(state="normal")
        self.add_attribute_row()  # Add one empty attribute row to start
    
    def save_current_secret(self):
        """Save the current secret to AWS"""
        secret_name = self.name_var.get().strip()
        
        # Validate secret name
        if not secret_name:
            messagebox.showerror("Validation Error", "Secret name is required.")
            return
        
        # Collect attributes
        attributes = {}
        for row in self.attribute_rows:
            key = row.get_key().strip()
            value = row.get_value()
            
            # Skip empty keys
            if key:
                attributes[key] = value
        
        # Check if this is a new secret or updating existing
        is_new = secret_name not in self.secrets_data
        
        # Update local data
        self.secrets_data[secret_name] = attributes
        
        # Save to AWS
        try:
            self.secrets_client.put_secret_value(
                SecretId=SECRET_PATH,
                SecretString=json.dumps(self.secrets_data)
            )
            
            messagebox.showinfo(
                "Success", 
                f"Secret '{secret_name}' {'created' if is_new else 'updated'} successfully."
            )
            
            # Refresh the secret list
            self.populate_secret_list()
            
            # Select the saved secret
            self.load_secret_details(secret_name)
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save secret: {str(e)}")
    
    def delete_current_secret(self):
        """Delete the current secret after confirmation"""
        secret_name = self.name_var.get().strip()
        
        if not secret_name or secret_name not in self.secrets_data:
            return
        
        # Confirm deletion
        if not messagebox.askyesno(
            "Confirm Deletion", 
            f"Are you sure you want to delete the secret '{secret_name}'?"
        ):
            return
        
        # Delete from local data
        del self.secrets_data[secret_name]
        
        # Save to AWS
        try:
            self.secrets_client.put_secret_value(
                SecretId=SECRET_PATH,
                SecretString=json.dumps(self.secrets_data)
            )
            
            messagebox.showinfo("Success", f"Secret '{secret_name}' deleted successfully.")
            
            # Refresh the secret list
            self.populate_secret_list()
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to delete secret: {str(e)}")


if __name__ == "__main__":
    app = AWSVaultLite()
    app.mainloop()
