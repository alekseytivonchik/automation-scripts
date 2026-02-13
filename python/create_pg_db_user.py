#!/usr/bin/env python3
import getpass
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
    specials = "!@#$%^&*()-_=+,.?~"
    alphabet = string.ascii_letters + string.digits + specials
    while True:
        pwd = "".join(secrets.choice(alphabet) for _ in range(length))
        if (any(c.islower() for c in pwd)
                and any(c.isupper() for c in pwd)
                and any(c.isdigit() for c in pwd)
                and any(c in specials for c in pwd)):
            return pwd


def main() -> None:
    print("=== PostgreSQL: создать пользователя (если нет), создать БД и выдать полные права (public schema) ===")

    host = prompt_non_empty("PostgreSQL host", "localhost")
    port = prompt_int("PostgreSQL port", 5432)

    admin_user = prompt_non_empty("Логин для подключения к PostgreSQL (нужны права CREATE ROLE/DB)")
    admin_pass = getpass.getpass("Пароль для подключения к PostgreSQL: ")

    new_db = prompt_non_empty("Имя создаваемой базы данных")
    target_user = prompt_non_empty("Имя пользователя, которому выдать права (создадим если нет)")

    pwd_len = prompt_int("Длина генерируемого пароля (если будем создавать/обновлять)", 24)

    maintenance_db = "postgres"
    admin_dsn = f"host={host} port={port} dbname={maintenance_db} user={admin_user} password={admin_pass}"

    generated_password: str | None = None

    try:
        # 1) Роль/БД (в postgres), autocommit нужен для CREATE DATABASE
        with psycopg.connect(admin_dsn, autocommit=True) as conn:
            with conn.cursor() as cur:
                # Проверим роль
                cur.execute("SELECT rolsuper FROM pg_roles WHERE rolname = %s", (target_user,))
                row = cur.fetchone()

                if row is None:
                    # создать роль
                    generated_password = gen_password(pwd_len)
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
                            role=sql.Identifier(target_user),
                            password=sql.Literal(generated_password),
                        )
                    )
                    print(f"[OK] Роль создана: {target_user}")
                    print("\n=== Сгенерированный пароль (stdout) ===")
                    print(generated_password)
                    print("=== /пароль ===\n")

                else:
                    # Роль существует — убедимся что не суперюзер
                    if bool(row[0]) is True:
                        raise RuntimeError(
                            f"Пользователь '{target_user}' является SUPERUSER. Это запрещено требованиями.\n"
                            f"Снимите SUPERUSER вручную: ALTER ROLE {target_user} NOSUPERUSER;"
                        )

                    # Предложим обновить пароль
                    ans = input(f"Пользователь '{target_user}' уже существует. Обновить пароль? [y/N]: ").strip().lower()
                    if ans in ("y", "yes", "да", "д"):
                        generated_password = gen_password(pwd_len)
                        cur.execute(
                            sql.SQL("ALTER ROLE {role} WITH PASSWORD {password} NOSUPERUSER;")
                            .format(role=sql.Identifier(target_user), password=sql.Literal(generated_password))
                        )
                        print(f"[OK] Пароль обновлён: {target_user}")
                        print("\n=== Сгенерированный пароль (stdout) ===")
                        print(generated_password)
                        print("=== /пароль ===\n")
                    else:
                        print("[INFO] Пароль не меняли.")

                # На всякий случай закрепим NOSUPERUSER (если создали или если админ хочет явно)
                cur.execute(
                    sql.SQL("ALTER ROLE {role} NOSUPERUSER;").format(role=sql.Identifier(target_user))
                )

                # Создать БД если нет, иначе назначить владельца
                cur.execute("SELECT 1 FROM pg_database WHERE datname = %s", (new_db,))
                db_exists = cur.fetchone() is not None

                if not db_exists:
                    cur.execute(
                        sql.SQL("CREATE DATABASE {db} OWNER {owner};")
                        .format(db=sql.Identifier(new_db), owner=sql.Identifier(target_user))
                    )
                    print(f"[OK] База данных создана: {new_db} (owner={target_user})")
                else:
                    print(f"[INFO] База уже существует: {new_db}")
                    cur.execute(
                        sql.SQL("ALTER DATABASE {db} OWNER TO {owner};")
                        .format(db=sql.Identifier(new_db), owner=sql.Identifier(target_user))
                    )
                    print(f"[OK] Владелец выставлен: {new_db} -> {target_user}")

                # Права на БД (дублируем, хотя owner и так имеет)
                cur.execute(
                    sql.SQL("GRANT ALL PRIVILEGES ON DATABASE {db} TO {role};")
                    .format(db=sql.Identifier(new_db), role=sql.Identifier(target_user))
                )
                print(f"[OK] GRANT ALL ON DATABASE {new_db} TO {target_user}")

        # 2) Права внутри public-схемы (подключаемся к целевой БД)
        target_dsn = f"host={host} port={port} dbname={new_db} user={admin_user} password={admin_pass}"
        with psycopg.connect(target_dsn, autocommit=True) as conn:
            with conn.cursor() as cur:
                # На схему public: USAGE + CREATE
                cur.execute(
                    sql.SQL("GRANT USAGE, CREATE ON SCHEMA public TO {role};")
                    .format(role=sql.Identifier(target_user))
                )

                # На существующие объекты в public
                cur.execute(
                    sql.SQL("GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO {role};")
                    .format(role=sql.Identifier(target_user))
                )
                cur.execute(
                    sql.SQL("GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO {role};")
                    .format(role=sql.Identifier(target_user))
                )
                cur.execute(
                    sql.SQL("GRANT ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA public TO {role};")
                    .format(role=sql.Identifier(target_user))
                )

                # Дефолтные привилегии для будущих объектов,
                # создаваемых владельцем БД (target_user)
                cur.execute(
                    sql.SQL(
                        "ALTER DEFAULT PRIVILEGES FOR ROLE {owner} IN SCHEMA public "
                        "GRANT ALL PRIVILEGES ON TABLES TO {grantee};"
                    ).format(owner=sql.Identifier(target_user), grantee=sql.Identifier(target_user))
                )
                cur.execute(
                    sql.SQL(
                        "ALTER DEFAULT PRIVILEGES FOR ROLE {owner} IN SCHEMA public "
                        "GRANT ALL PRIVILEGES ON SEQUENCES TO {grantee};"
                    ).format(owner=sql.Identifier(target_user), grantee=sql.Identifier(target_user))
                )
                cur.execute(
                    sql.SQL(
                        "ALTER DEFAULT PRIVILEGES FOR ROLE {owner} IN SCHEMA public "
                        "GRANT ALL PRIVILEGES ON FUNCTIONS TO {grantee};"
                    ).format(owner=sql.Identifier(target_user), grantee=sql.Identifier(target_user))
                )

                print(f"[OK] Права в schema public настроены для {target_user}")

        print("\nГотово.")
        print("\nПроверка подключения (пример):")
        if generated_password:
            print(f'psql "host={host} port={port} dbname={new_db} user={target_user} password={generated_password}"')
        else:
            print(f'psql "host={host} port={port} dbname={new_db} user={target_user}"')

    except Exception as e:
        print("\n[ERROR] Не удалось выполнить операцию:")
        print(e)
        sys.exit(3)


if __name__ == "__main__":
    main()
