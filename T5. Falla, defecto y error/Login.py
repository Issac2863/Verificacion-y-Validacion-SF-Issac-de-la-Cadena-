usuarios_registrados = {
    "usuario1": "claveSecreta123",
    "admin": "adminP@ssw0rd",
    "testuser": "test1"
}

# Contador de intentos de inicio de sesión
intentos_maximos = 3

def verificar_credenciales(usuario, contrasena):
    """
    Verifica las credenciales del usuario.
    Contiene defectos introducidos a propósito.
    """
    # DEFECTO 1: Sensibilidad incorrecta a mayúsculas/minúsculas en el nombre de usuario.
    #   Descripción: El sistema debería permitir que el nombre de usuario no sea
    #   sensible a mayúsculas/minúsculas para mejorar la usabilidad (ej. "Usuario1"
    #   debería ser igual a "usuario1"). Sin embargo, aquí se compara de forma exacta,
    #   lo que podría considerarse un defecto si el requisito fuera diferente.
    #   Para este ejemplo, asumiremos que el requisito era que fuera insensible,
    #   por lo que la comparación directa es un defecto.
    #   Si el usuario ingresa "Usuario1" en lugar de "usuario1", el inicio de sesión fallará
    #   aunque la contraseña sea correcta. Esto es un FALLO causado por este DEFECTO.
    if usuario in usuarios_registrados:
        # DEFECTO 2: Comparación de contraseña insegura y manejo incorrecto de longitud.
        #   Descripción: La contraseña se compara directamente. Además, hay un defecto
        #   adicional: si la contraseña almacenada tiene menos de 5 caracteres
        #   (lo cual es una mala práctica de por sí), se permite el acceso incluso
        #   si la contraseña ingresada es diferente pero coincide en los primeros N caracteres.
        #   Esto es un grave DEFECTO de seguridad.
        #   Ejemplo de FALLO: Si el usuario es "testuser" (contraseña "test1") e ingresa
        #   "test", el sistema podría permitir el acceso. (Corregido para que el fallo sea más evidente)
        #   Para este ejemplo, el defecto específico es que no valida la longitud mínima
        #   de la contraseña ingresada antes de hacer una comparación potencialmente problemática.
        #   Además, la comparación directa de contraseñas es en sí misma un defecto de seguridad.

        # ERROR (conceptual del programador al diseñar esta lógica):
        #   El programador podría haber pensado erróneamente que truncar la
        #   comparación o no validar longitudes era una forma de "simplificar"
        #   sin darse cuenta de la vulnerabilidad creada (el defecto).

        if len(usuarios_registrados[usuario]) < 5 and usuarios_registrados[usuario] == contrasena[:len(usuarios_registrados[usuario])]:
            # Este es el comportamiento defectuoso para contraseñas cortas (menos de 5 caracteres)
            # Si la contraseña almacenada es "test" (4 caracteres) y el usuario ingresa "test12345",
            # la comparación contrasena[:len(usuarios_registrados[usuario])] resultará en "test" == "test" -> True
            # ¡Esto es un FALLO de seguridad!
            print("FALLO DE SEGURIDAD EXPLOTADO (Defecto 2): Acceso concedido con contraseña parcialmente correcta.")
            return True
        elif usuarios_registrados[usuario] == contrasena:
            return True
        else:
            # FALLO 1 (causado por el Defecto 1 o por contraseña incorrecta):
            #   Si el usuario era "Usuario1" en lugar de "usuario1", aquí se reportaría
            #   como contraseña incorrecta aunque la contraseña en sí fuera correcta para "usuario1".
            #   O simplemente, la contraseña es incorrecta.
            print("Fallo: Contraseña incorrecta.")
            return False
    else:
        # FALLO: Usuario no encontrado. Esto podría ser debido al Defecto 1 si el usuario
        #        escribió "Admin" en lugar de "admin".
        print(f"Fallo: Usuario '{usuario}' no encontrado.")
        return False

def modulo_inicio_sesion():
    """
    Módulo principal de inicio de sesión.
    Permite al usuario hasta `intentos_maximos` para iniciar sesión.
    """
    intentos_actuales = 0
    print("Bienvenido al Sistema. Por favor, inicie sesión.")

    while intentos_actuales < intentos_maximos:
        print(f"\nIntento {intentos_actuales + 1} de {intentos_maximos}")
        usuario_ingresado = input("Ingrese su nombre de usuario: ")
        contrasena_ingresada = input("Ingrese su contraseña: ")

        # ERROR POTENCIAL DEL USUARIO: Ingresar credenciales vacías.
        #   Aunque el sistema podría manejarlo (o no, generando un fallo si no hay validación),
        #   el acto de ingresar datos vacíos es un error del usuario.
        if not usuario_ingresado or not contrasena_ingresada:
            print("Error del usuario: El nombre de usuario y la contraseña no pueden estar vacíos.")
            # Aquí se podría considerar no contar esto como un intento fallido formal,
            # o sí, dependiendo de los requisitos. Para este ejemplo, lo contamos.
            intentos_actuales += 1
            # DEFECTO 3 (Manejo de intentos): Si no se incrementara `intentos_actuales` aquí,
            # y se continuara el bucle, se podría dar lugar a intentos ilimitados si el usuario
            # solo presiona Enter. Esto sería un defecto en la lógica de conteo de intentos.
            # En este caso, sí lo incrementamos, evitando ese defecto particular.
            if intentos_actuales >= intentos_maximos:
                print("Ha excedido el número máximo de intentos.")
            continue

        if verificar_credenciales(usuario_ingresado, contrasena_ingresada):
            print(f"\n¡Inicio de sesión exitoso! Bienvenido, {usuario_ingresado}.")
            # Aquí iría la lógica para acceder al sistema principal.
            return True
        else:
            intentos_actuales += 1
            if intentos_actuales < intentos_maximos:
                print(f"Credenciales incorrectas. Le quedan {intentos_maximos - intentos_actuales} intentos.")
            else:
                print("Ha excedido el número máximo de intentos. Acceso denegado.")
                # FALLO FINAL: El usuario no pudo acceder al sistema después de múltiples intentos.
                # Este es el resultado esperado del RF si las credenciales son consistentemente incorrectas,
                # o si los defectos impiden un inicio de sesión válido.

    return False

# Ejecutar el módulo de inicio de sesión
if __name__ == "__main__":
    modulo_inicio_sesion()

    print("\n--- Demostración de Fallos Específicos ---")

    print("\nPrueba de FALLO 1 (causado por DEFECTO 1 - sensibilidad de mayúsculas en usuario):")
    print("Intentando iniciar sesión con 'Usuario1' (debería ser 'usuario1') y 'claveSecreta123'")
    # Para aislar esta prueba, llamamos directamente a verificar_credenciales
    verificar_credenciales("Usuario1", "claveSecreta123")
    # Salida esperada: "Fallo: Usuario 'Usuario1' no encontrado."

    print("\nPrueba de FALLO 2 (causado por DEFECTO 2 - comparación insegura para contraseñas cortas):")
    print("Intentando iniciar sesión con 'testuser' (contraseña real 'test1') y contraseña ingresada 'test'")
    verificar_credenciales("testuser", "test") # Debería conceder acceso debido al defecto.
    # Salida esperada: "FALLO DE SEGURIDAD EXPLOTADO (Defecto 2): Acceso concedido con contraseña parcialmente correcta."

    print("\nPrueba de FALLO 3 (Contraseña incorrecta estándar):")
    print("Intentando iniciar sesión con 'usuario1' y 'contraseñaIncorrecta'")
    verificar_credenciales("usuario1", "contraseñaIncorrecta")
    # Salida esperada: "Fallo: Contraseña incorrecta."