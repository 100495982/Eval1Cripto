from UserManager import UserAuthenticator
from guiManager import GUIManager

#Inicio de la funcion que se ejecutara al arrancar el programa.
def main():
    # print("Welcome!")

    #Bucle que se ejecutara hasta que el usuario decida salir.
    while True:
        gui = GUIManager()
        gui.initial_options()

        #Seleccion de la opcion.
        option = input()
        if option == "1":
            #Registro de un nuevo usuario.
            success = UserAuthenticator.register()
            if success:
                print("You may now log in with your new account.")
        elif option == "2":
            # Si el usuario se ha logueado correctamente, se ejecutara el bucle de la sesion.
            session = UserAuthenticator.login()
            if session:
                gui.print_msg("\nYou are logged in.", "green")
                while True:
                    gui.session_options()
                    action = input().strip().lower()
                    if action == "send":
                        gui.print_msg("Enter recipient's username: ")
                        receiver = input()
                        gui.print_msg("Enter your message: ")
                        message = input()
                        session.encrypt_message(receiver, message)
                    elif action == "read":
                        session.decrypt_message()
                    elif action == "exit":
                        session.end_session()
                        gui.print_msg("Logged out successfully.", "green")
                        break
                    else:
                        gui.print_msg("Invalid option.", "red")
        elif option == "3":
            #Salida del programa.
            gui.print_msg("Exiting program.", "red")
            break
        else:
            gui.print_msg("Invalid option.", "red")


if __name__ == "__main__":
    main()
