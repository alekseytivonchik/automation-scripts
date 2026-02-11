#!/usr/bin/env python3
import secrets
import string
import sys

try:
    import psycopg
    from psycopg import sql
except ImportError:
    print("Не найден psycopg. Установите: pip install psycopg[binary]")
    sys.exit(1)


def prompt_non_empty(label: str, default: str | None = None) -> str:
    while True:
        v = input(f"{label}" + (f" [{default}]" if default else "") + ": ").strip()
        if not v and default is not None:
            return default
        if v:
            return v
        print("Значение не должно быть пустым.")


def prompt_int(label: str, default: int) -> int:
    while True:
        v = input(f"{label} [{default}]: ").strip()
        if not v:
            return default
        try:
            return int(v)
        except ValueError:
            print("Введите целое число.")


def gen_password(length: int = 24) -> str:
    # Без кавычек и обратного слеша, чтобы меньше шансов на проблемы при копипасте/шелле.
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+,.?~"
    # Гарантируем, что будут разные классы символов
    while True:
        pwd = "".join(secrets.choice(alphabet) for _ in range(length))
        if (any(c.islower() for c in pwd)
                and any(c.isupper() for c in pwd)
                and any(c.isdigit() for c in pwd)
                and any(c in "!@#$%^&*()-_=+,.?~" for c in pwd)):
            return pwd


def main() -> None:
    print("=== Создание пользователя и базы данных PostgreSQL ===")

    host = prompt_non_empty("PostgreSQL host", "localhost")
    port = prompt_int("PostgreSQL port", 5432)

    admin_user = prompt_non_empty("Логин для подключения к PostgreSQL")
    admin_pass = prompt_non_empty("Пароль для подключения к PostgreSQL")  # намеренно через input, чтобы можно было из буфера вставлять

    new_db = prompt_non_empty("Имя создаваемой базы данных")
    new_user = prompt_non_empty("Имя создаваемого пользователя (role)")

    pwd_len = prompt_int("Длина генерируемого пароля", 24)
    new_pass = gen_password(pwd_len)

    print("\n=== Сгенерированный пароль (stdout) ===")
    print(new_pass)
    print("=== /пароль ===\n")

    maintenance_db = "postgres"
    admin_dsn = f"host={host} port={port} dbname={maintenance_db} user={admin_user} password={admin_pass}"

    try:
        # 1) Создать роль и БД (подключение к postgres), autocommit нужен для CREATE DATABASE
        with psycopg.connect(admin_dsn, autocommit=True) as conn:
            with conn.cursor() as cur:
                # role
                cur.execute("SELECT 1 FROM pg_roles WHERE rolname = %s", (new_user,))
                role_exists = cur.fetchone() is not None

                if not role_exists:
                    cur.execute(
                        sql.SQL(
                            """
                            CREATE ROLE {role}
                            WITH
                                LOGIN
                                PASSWORD {password}
                                NOSUPERUSER
                                NOCREATEDB
                                NOCREATEROLE
                                NOINHERIT
                                NOREPLICATION
                                NOBYPASSRLS;
                            """
                        ).format(
                            role=sql.Identifier(new_user),
                            password=sql.Literal(new_pass),
                        )
                    )

                    print(f"[OK] Роль создана: {new_user}")
                else:
                    cur.execute(
                        sql.SQL(
                            "ALTER ROLE {role} WITH PASSWORD {password} NOSUPERUSER;"
                        ).format(
                            role=sql.Identifier(new_user),
                            password=sql.Literal(new_pass),
                        )
                    )
                    print(f"[OK] Роль уже существовала, пароль обновлён: {new_user}")

                # db
                cur.execute("SELECT 1 FROM pg_database WHERE datname = %s", (new_db,))
                db_exists = cur.fetchone() is not None

                if not db_exists:
                    cur.execute(
                        sql.SQL("CREATE DATABASE {db} OWNER {owner};")
                        .format(db=sql.Identifier(new_db), owner=sql.Identifier(new_user))
                    )
                    print(f"[OK] База данных создана: {new_db} (owner={new_user})")
                else:
                    cur.execute(
                        sql.SQL("ALTER DATABASE {db} OWNER TO {owner};")
                        .format(db=sql.Identifier(new_db), owner=sql.Identifier(new_user))
                    )
                    print(f"[OK] База уже существовала, владелец выставлен: {new_db} -> {new_user}")

                # права на БД (хотя owner и так имеет, но явно)
                cur.execute(
                    sql.SQL("GRANT ALL PRIVILEGES ON DATABASE {db} TO {role};")
                    .format(db=sql.Identifier(new_db), role=sql.Identifier(new_user))
                )
                print(f"[OK] Выданы права на БД: GRANT ALL ON DATABASE {new_db} TO {new_user}")

        # 2) Права внутри public (подключение уже к созданной/целевой БД)
        target_dsn = f"host={host} port={port} dbname={new_db} user={admin_user} password={admin_pass}"
        with psycopg.connect(target_dsn, autocommit=True) as conn:
            with conn.cursor() as cur:
                # На схему public
                cur.execute(
                    sql.SQL("GRANT USAGE, CREATE ON SCHEMA public TO {role};")
                    .format(role=sql.Identifier(new_user))
                )

                # На существующие объекты в public
                cur.execute(
                    sql.SQL("GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO {role};")
                    .format(role=sql.Identifier(new_user))
                )
                cur.execute(
                    sql.SQL("GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO {role};")
                    .format(role=sql.Identifier(new_user))
                )
                cur.execute(
                    sql.SQL("GRANT ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA public TO {role};")
                    .format(role=sql.Identifier(new_user))
                )

                # Дефолтные привилегии на будущие объекты, создаваемые владельцем БД (т.е. новым юзером)
                # Это полезно, если потом вы будете создавать объекты под другим владельцем — но для owner это обычно не требуется.
                # Тем не менее зададим на всякий случай "самому себе".
                cur.execute(
                    sql.SQL("ALTER DEFAULT PRIVILEGES FOR ROLE {owner} IN SCHEMA public "
                            "GRANT ALL PRIVILEGES ON TABLES TO {grantee};")
                    .format(owner=sql.Identifier(new_user), grantee=sql.Identifier(new_user))
                )
                cur.execute(
                    sql.SQL("ALTER DEFAULT PRIVILEGES FOR ROLE {owner} IN SCHEMA public "
                            "GRANT ALL PRIVILEGES ON SEQUENCES TO {grantee};")
                    .format(owner=sql.Identifier(new_user), grantee=sql.Identifier(new_user))
                )
                cur.execute(
                    sql.SQL("ALTER DEFAULT PRIVILEGES FOR ROLE {owner} IN SCHEMA public "
                            "GRANT ALL PRIVILEGES ON FUNCTIONS TO {grantee};")
                    .format(owner=sql.Identifier(new_user), grantee=sql.Identifier(new_user))
                )

                print(f"[OK] Права в schema public выданы для {new_user} (USAGE/CREATE + ALL на объекты)")

        print("\nГотово.")
        print("\nПодключение (пример):")
        print(f'psql "host={host} port={port} dbname={new_db} user={new_user} password={new_pass}"')

    except Exception as e:
        print("\n[ERROR] Не удалось выполнить операцию:")
        print(e)
        sys.exit(3)


if __name__ == "__main__":
    main()
