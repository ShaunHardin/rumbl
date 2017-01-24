defmodule Rumbl.AuthTest do
  use Rumbl.ConnCase
  alias Rumbl.Auth

  setup %{conn: conn} do
    conn =
      conn
      |> bypass_through(Rumbl.Router, :browser)
      |> get("/")

    {:ok, %{conn: conn}}
  end

  test "authenticate_user halts when no current_user exists",
    %{conn: conn} do

    conn =
      conn
      |> assign(:current_user, nil)
      |> Auth.authenticate_user([])
    assert conn.halted
  end

  test "authenticate_user continues when the current_user exists",
    %{conn: conn} do

    conn =
      conn
      |> assign(:current_user, %Rumbl.User{})
      |> Auth.authenticate_user([])

    refute conn.halted
  end

  test "login puts the user in the session", %{conn: conn} do
    login_conn =
      conn
      |> Auth.login(%Rumbl.User{id: 123})
      |> send_resp(:ok, "")

    next_conn = get(login_conn, "/")
    assert get_session(next_conn, :user_id) == 123
  end

  test "logout drops the session", %{conn: conn} do
    logout_conn =
      conn
      |> put_session(:user_id, 123)
      |> Auth.logout()
      |> send_resp(:ok, "")

    next_conn = get(logout_conn, "/")
    refute get_session(next_conn, :user_id)
  end

  test "call places user from session into assigns", %{conn: conn} do
    user = insert_user()
    conn =
      conn
      |> put_session(:user_id, user.id)
      |> Auth.call(Repo)

    assert conn.assigns.current_user.id == user.id
  end

  test "call with no session sets current_user assign to nil", %{conn: conn} do
    conn = Auth.call(conn, Repo)
    assert conn.assigns.current_user == nil
  end

  test "login with a valid username and pass", %{conn: conn} do
    username = "me"
    password = "secret"
    user = insert_user(username: username, password: password)
    {:ok, conn} =
      Auth.login_by_username_and_pass(conn, username, password, repo: Repo)

    assert conn.assigns.current_user.id == user.id
  end

  test "login with a not found user", %{conn: conn} do
    {:error, :not_found, conn} =
      Auth.login_by_username_and_pass(conn, "nobody", "nothing", repo: Repo)

    assert conn.assigns.current_user == nil
  end

  test "login with password mismatch", %{conn: conn} do
    username = "me"
    password = "secret"
    _user = insert_user(username: username, password: password)
    {:error, :unauthorized, conn} =
      Auth.login_by_username_and_pass(conn, username, "wrong", repo: Repo)

    assert conn.assigns.current_user == nil
  end
end
