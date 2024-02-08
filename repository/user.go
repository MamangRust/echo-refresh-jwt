package repository

import (
	"echoauthjwt/models"
	"fmt"
	"sync"
)

type UserRepository interface {
	ReadAll() []models.User
	Read(userID int) (*models.User, error)
	ReadByEmail(email string) (*models.User, error)
	Create(user models.User) (*models.User, error)
	Update(userID int, newUser models.User) (*models.User, error)
	Delete(userID int) bool
}

type userRepository struct {
	mu     sync.RWMutex
	users  map[int]models.User
	nextID int
}

func NewUserRepository() *userRepository {
	return &userRepository{
		users:  make(map[int]models.User),
		nextID: 1,
	}
}

func (ds *userRepository) ReadAll() []models.User {
	ds.mu.RLock()
	defer ds.mu.RUnlock()

	users := make([]models.User, 0, len(ds.users))
	for _, user := range ds.users {
		users = append(users, user)
	}

	return users
}

func (ds *userRepository) Read(userID int) (*models.User, error) {
	ds.mu.RLock()
	defer ds.mu.RUnlock()

	for _, user := range ds.users {
		if user.UserID == userID {
			return &user, nil
		}
	}

	return nil, fmt.Errorf("user with ID %d not found", userID)
}

func (ds *userRepository) ReadByEmail(email string) (*models.User, error) {
	ds.mu.RLock()
	defer ds.mu.RUnlock()

	for _, user := range ds.users {
		if user.Email == email {
			return &user, nil
		}
	}

	return nil, fmt.Errorf("user with email %s not found", email)
}

func (ds *userRepository) Create(user models.User) (*models.User, error) {
	ds.mu.Lock()
	defer ds.mu.Unlock()

	if _, exists := ds.users[user.UserID]; exists {
		return nil, fmt.Errorf("user with ID %d already exists", user.UserID)
	}

	user.UserID = ds.nextID
	ds.users[user.UserID] = user
	ds.nextID++

	return &user, nil
}

func (ds *userRepository) Update(userID int, newUser models.User) (*models.User, error) {
	ds.mu.Lock()
	defer ds.mu.Unlock()

	if _, ok := ds.users[userID]; ok {
		newUser.UserID = userID
		ds.users[userID] = newUser
		return &newUser, nil
	}

	return nil, fmt.Errorf("user with ID %d not found", userID)
}

func (ds *userRepository) Delete(userID int) bool {
	ds.mu.Lock()
	defer ds.mu.Unlock()

	if _, ok := ds.users[userID]; ok {
		delete(ds.users, userID)
		return true
	}

	return false
}
