<?php

namespace App\Controller;

use App\Entity\User;
use Doctrine\ORM\EntityManagerInterface;
use Lexik\Bundle\JWTAuthenticationBundle\Services\JWTTokenManagerInterface;
use OpenApi\Attributes as OA;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;
use Symfony\Component\Routing\Attribute\Route;

use Symfony\Component\Serializer\SerializerInterface;

class AuthController extends AbstractController
{
    #[Route('/api/register', name: 'app_register', methods: ['POST'])]
    #[OA\Post(
        summary: "Register a new user",
        description: "Creates a new user account and returns the user details",
        requestBody: new OA\RequestBody(
            required: true,
            content: new OA\JsonContent(
                type: "object",
                properties: [
                    new OA\Property(property: "email", type: "string", example: "user@example.com"),
                    new OA\Property(property: "password", type: "string", example: "securepassword")
                ]
            )
        ),
        responses: [
            new OA\Response(
                response: 201,
                description: "User created successfully",
                content: new OA\JsonContent(
                    type: "object",
                    properties: [
                        new OA\Property(property: "id", type: "integer", example: 1),
                        new OA\Property(property: "username", type: "string", example: "user@example.com"),
                        new OA\Property(property: "password", type: "string", example: "password"),
                        new OA\Property(property: "roles", type: "array", items: new OA\Items(type: "string"))
                    ]
                )
            ),
            new OA\Response(
                response: 400,
                description: "Invalid input"
            )
        ]
    )]
    public function register(
        Request $request,
        SerializerInterface $serializer,
        UserPasswordHasherInterface $passwordHasher,
        EntityManagerInterface $entityManager
    ): JsonResponse {
        $user = $serializer->deserialize($request->getContent(), User::class, 'json');

        $password = bin2hex($user->getPassword());

        $encodedPassword = $passwordHasher->hashPassword($user, $user->getPassword());

        $user->setPassword($encodedPassword);
        $user->setRoles(['ROLE_USER']);

        $entityManager->persist($user);
        $entityManager->flush();

        $data = [
            'id' => $user->getId(),
            'username' => $user->getEmail(),
            'password' => $password,
            'roles' => $user->getRoles(),
        ];

        return new JsonResponse($data, Response::HTTP_CREATED);
    }

    #[Route('/api/login', name: 'app_login', methods: ['POST'])]
    #[OA\Post(
        summary: "User login",
        description: "Authenticates a user and returns a JWT token",
        requestBody: new OA\RequestBody(
            required: true,
            content: new OA\JsonContent(
                type: "object",
                properties: [
                    new OA\Property(property: "email", type: "string", example: "user@example.com"),
                    new OA\Property(property: "password", type: "string", example: "securepassword")
                ]
            )
        ),
        responses: [
            new OA\Response(
                response: 200,
                description: "Login successful",
                content: new OA\JsonContent(
                    type: "object",
                    properties: [
                        new OA\Property(property: "token", type: "string", example: "your.jwt.token")
                    ]
                )
            ),
            new OA\Response(
                response: 400,
                description: "Invalid credentials"
            )
        ]
    )]
    public function login(
        Request $request,
        JWTTokenManagerInterface $jwtEncoder,
        UserPasswordHasherInterface $passwordEncoder,
        EntityManagerInterface $em
    ): JsonResponse {
        $data = json_decode($request->getContent(), true);
        $email = $data['email'] ?? '';
        $password = $data['password'] ?? '';

        $user = $em->getRepository(User::class)->findOneBy(['email' => $email]);

        if (!$user || !$passwordEncoder->isPasswordValid($user, $password)) {
            return new JsonResponse(['error' => 'Invalid credentials'], JsonResponse::HTTP_BAD_REQUEST);
        }

        $token = $jwtEncoder->create($user);

        return new JsonResponse(['token' => $token]);
    }
}
