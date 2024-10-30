from UserManager import UserAuthenticator

def main():
    print("Welcome!")
    while True:
        print("\nPlease choose an option:")
        print("1. Register")
        print("2. Login")
        print("3. Exit")

        option = input("Select an option (1, 2, or 3): ")
        if option == "1":
            success = UserAuthenticator.register()
            if success:
                print("You may now log in with your new account.")
        elif option == "2":
            session = UserAuthenticator.login()
            if session:
                while True:
                    print("\nYou are logged in.")
                    action = input(
                        "Type 'send' to send a message, 'read' to read messages, or 'exit' to log out: ").strip().lower()
                    if action == "send":
                        receiver = input("Enter recipient's username: ")
                        message = input("Enter your message: ")
                        session.encrypt_message(receiver, message)
                    elif action == "read":
                        session.decrypt_message()
                    elif action == "exit":
                        session.end_session()
                        print("Logged out successfully.")
                        break
                    else:
                        print("Invalid option.")
        elif option == "3":
            print("Exiting program.")
            break
        else:
            print("Invalid option.")


if __name__ == "__main__":
    main()