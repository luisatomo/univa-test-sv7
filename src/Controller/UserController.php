<?php

namespace App\Controller;

use App\Entity\User;
use OpenApi\Attributes as OA;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\SecurityBundle\Security;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;
use Symfony\Component\Security\Core\Exception\AccessDeniedException;
use Symfony\Component\Serializer\SerializerInterface;
use Nelmio\ApiDocBundle\Annotation\Security as OASecurity;
use Nelmio\ApiDocBundle\Annotation\Model;
use Symfony\Component\Serializer\Context\Normalizer\ObjectNormalizerContextBuilder;

#[Route('/api/user')]
class UserController extends AbstractController
{
    public function __construct(
        private Security $security,
        private EntityManagerInterface $entityManager,
        private UserPasswordHasherInterface $passwordEncoder,
        private SerializerInterface $serializer
    ) { }

    #[Route('/', name: 'user_index', methods: ['GET'])]
    #[OASecurity(name: 'Bearer')]
    #[OA\Get(
        summary: "List users",
        description: "Returns a list of users",
        responses: [
        new OA\Response(
            response: 200,
            description: 'Returns an array of users',
            content: new OA\JsonContent(
                type: 'array',
                items: new OA\Items(ref: new Model(type: User::class, groups: ['list_user']))
            )
        ),
        new OA\Response(
            response: 401,
            description: 'Not Authorized',
        )]
    )]
    public function index(): JsonResponse
    {
        if ($this->isAdmin()) {
            $users = $this->entityManager->getRepository(User::class)->findAll();
        } else {
            $users = [$this->getCurrentUser()];
        }
        $context = (new ObjectNormalizerContextBuilder())
            ->withGroups('list_user')
            ->toArray();
        $serializedUsers = $this->serializer->serialize($users, 'json', $context);

        return new JsonResponse($serializedUsers, Response::HTTP_OK, [], true);
    }

    #[Route('/{uuid}', name: 'user_show', methods: ['GET'])]
    #[OASecurity(name: 'Bearer')]
    #[OA\Get(
        summary: "List specific user by UUID",
        description: "Returns one user",
        responses: [
        new OA\Response(
            response: 200,
            description: 'Returns one user',
            content: new OA\JsonContent(
                ref: new Model(type: User::class, groups: ['list_user'])
            )
        ),
        new OA\Response(
            response: 401,
            description: 'Not Authorized',
        )]
    )]
    public function show(string $uuid): JsonResponse
    {
        $user = $this->entityManager->getRepository(User::class)->findOneBy(['uuid' => $uuid]);
        if (!$user) {
            return new JsonResponse(['message' => 'User not found'], Response::HTTP_NOT_FOUND);
        }

        $this->authorizeAdminOrOwner($user);

        $context = (new ObjectNormalizerContextBuilder())
            ->withGroups('list_user')
            ->toArray();

        $serializedUser = $this->serializer->serialize($user, 'json', $context);

        return new JsonResponse($serializedUser, Response::HTTP_OK, [], true);
    }

    #[Route('/', name: 'user_create', methods: ['POST'])]
    #[OASecurity(name: 'Bearer')]
    #[OA\Post(
        summary: "Create a new user",
        description: "Creates a new user account.",
        requestBody: new OA\RequestBody(
            required: true,
            content: new OA\JsonContent(
                type: "object",
                properties: [
                    new OA\Property(property: "email", type: "string", example: "user@example.com", required: []),
                    new OA\Property(property: "password", type: "string", example: "password123", required: []),
                    new OA\Property(
                        property: "roles",
                        type: "array",
                        items: new OA\Items(type: "string", example: "ROLE_USER", required: [])
                    )
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
                        new OA\Property(property: "uuid", type: "string", example: "492d3d32-38cb-40c4-af14-4e7d5c080fe6"),
                        new OA\Property(property: "email", type: "string", example: "user@example.com"),
                        new OA\Property(property: "roles", type: "array", items: new OA\Items(type: "string", example: "ROLE_USER")),
                    ]
                )
            ),
            new OA\Response(
                response: 400,
                description: "Invalid input",
            ),
        ],
    )]
    public function create(Request $request): JsonResponse
    {
        $this->denyAccessUnlessGranted('ROLE_ADMIN');

        $user = $this->serializer->deserialize($request->getContent(), User::class, 'json');

        $encodedPassword = $this->passwordEncoder->hashPassword($user, $user->getPassword());

        $user->setPassword($encodedPassword);

        $this->entityManager->persist($user);
        $this->entityManager->flush();

        $context = (new ObjectNormalizerContextBuilder())
            ->withGroups('list_user')
            ->toArray();

        $serializedUser = $this->serializer->serialize($user, 'json', $context);

        return new JsonResponse($serializedUser, Response::HTTP_CREATED);
    }

    #[Route('/{uuid}', name: 'user_update', methods: ['PUT'])]
    #[OASecurity(name: 'Bearer')]
    #[OA\Put(
        summary: "Update a user",
        description: "Owner or admin updates a user.",
        requestBody: new OA\RequestBody(
            required: true,
            content: new OA\JsonContent(
                type: "object",
                properties: [
                    new OA\Property(property: "email", type: "string", example: "user@example.com", required: []),
                    new OA\Property(property: "password", type: "string", example: "password123", required: []),
                    new OA\Property(
                        property: "roles",
                        type: "array",
                        items: new OA\Items(type: "string", example: "ROLE_USER", required: [])
                    )
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
                        new OA\Property(property: "uuid", type: "string", example: "492d3d32-38cb-40c4-af14-4e7d5c080fe6"),
                        new OA\Property(property: "email", type: "string", example: "user@example.com"),
                        new OA\Property(property: "roles", type: "array", items: new OA\Items(type: "string", example: "ROLE_USER")),
                    ]
                )
            ),
            new OA\Response(
                response: 400,
                description: "Invalid input",
            ),
        ],
    )]
    public function update(Request $request, string $uuid): JsonResponse
    {
        $user = $this->entityManager->getRepository(User::class)->findOneBy(['uuid' => $uuid]);
        $updatedUser = $this->serializer->deserialize($request->getContent(), User::class, 'json');

        if (!$user) {
            return new JsonResponse(['message' => 'User not found'], Response::HTTP_NOT_FOUND);
        }

        $this->authorizeAdminOrOwner($user);

        $user->setEmail($updatedUser->getEmail());
        $user->setPassword($this->passwordEncoder->hashPassword($user, $updatedUser->getPassword()));

        if ($this->isAdmin()) {
            $user->setRoles($updatedUser->getRoles);
        }

        $this->entityManager->persist($user);
        $this->entityManager->flush();

        $context = (new ObjectNormalizerContextBuilder())
            ->withGroups('list_user')
            ->toArray();

        $serializedUser = $this->serializer->serialize($user, 'json', $context);

        $this->entityManager->flush();

        return new JsonResponse($serializedUser, Response::HTTP_CREATED);
    }

    #[Route('/{uuid}', name: 'user_delete', methods: ['DELETE'])]
    #[OASecurity(name: 'Bearer')]
    #[OA\Delete(
        summary: "Deletes a user",
        description: "Only admin can delete a user.",
        responses: [
            new OA\Response(
               response: 200,
               description: "User created successfully",
               content: new OA\JsonContent(
                   type: "object",
                   properties: [
                       new OA\Property(property: "message", type: "string", example: "User Deleted")
                   ]
               )
           ),
           new OA\Response(
               response: 403,
               description: "Forbidden Action",
           ),
        ],
    )]
    public function delete(string $uuid): JsonResponse
    {
        $user = $this->entityManager->getRepository(User::class)->findOneBy(['uuid' => $uuid]);
        if (!$user) {
            return new JsonResponse(['message' => 'User not found'], Response::HTTP_NOT_FOUND);
        }

        $this->authorizeAdmin();

        $this->entityManager->remove($user);
        $this->entityManager->flush();

        return new JsonResponse(['message' => 'User Deleted'], Response::HTTP_OK);
    }

    // Private methods

    private function getCurrentUser(): ?User
    {
        return $this->security->getUser();
    }

    private function isAdmin(): bool
    {
        $user = $this->getCurrentUser();
        return $user && in_array('ROLE_ADMIN', $user->getRoles(), true);
    }

    private function isOwner(User $user): bool
    {
        $currentUser = $this->getCurrentUser();
        return $currentUser && $currentUser->getId() === $user->getId();
    }

    private function authorizeAdminOrOwner(User $user): void
    {
        if (!$this->isAdmin() && !$this->isOwner($user)) {
            throw new AccessDeniedException('You are not authorized to perform this action.');
        }
    }

    private function authorizeAdmin(): void
    {
        if (!$this->isAdmin()) {
            throw new AccessDeniedException('You are not authorized to perform this action.');
        }
    }
}
