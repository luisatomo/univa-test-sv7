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
                items: new OA\Items(ref: new Model(type: User::class))
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
        $serializedUsers = $this->serializer->serialize($users, 'json');

        return new JsonResponse($serializedUsers, Response::HTTP_OK, [], true);
    }

    #[Route('/{id}', name: 'user_show', methods: ['GET'])]
    public function show(int $id): Response
    {
        $user = $this->entityManager->getRepository(User::class)->find($id);
        if (!$user) {
            return new Response('User not found', Response::HTTP_NOT_FOUND);
        }

        $this->authorizeAdminOrOwner($user);

        $serializedUser = $this->serializer->serialize($user, 'json');

        return new JsonResponse($serializedUser, Response::HTTP_OK, [], true);
    }

    #[Route('/', name: 'user_create', methods: ['POST'])]
    public function create(Request $request): Response
    {
        $this->denyAccessUnlessGranted('ROLE_ADMIN');

        $user = $this->serializer->deserialize($request->getContent(), User::class, 'json');

        $password = bin2hex($user->getPassword());

        $encodedPassword = $this->passwordEncoder->hashPassword($user, $user->getPassword());

        $user->setPassword($encodedPassword);

        $this->entityManager->persist($user);
        $this->entityManager->flush();

        $data = [
            'id' => $user->getId(),
            'username' => $user->getEmail(),
            'password' => $password,
            'roles' => $user->getRoles(),
        ];

        return new JsonResponse($data, Response::HTTP_CREATED);
    }

    #[Route('/{id}', name: 'user_update', methods: ['PUT'])]
    public function update(Request $request, int $id): Response
    {
        $user = $this->entityManager->getRepository(User::class)->find($id);
        if (!$user) {
            return new Response('User not found', Response::HTTP_NOT_FOUND);
        }

        $this->authorizeAdminOrOwner($user);

        $data = json_decode($request->getContent(), true);

        $user->setEmail($data['email']);
        $user->setPassword($this->passwordEncoder->encodePassword($user, $data['password']));
        $user->setRoles($data['roles'] ?? ['ROLE_USER']);

        $this->entityManager->flush();

        return new Response('User updated', Response::HTTP_OK);
    }

    #[Route('/{id}', name: 'user_delete', methods: ['DELETE'])]
    public function delete(int $id): Response
    {
        $user = $this->entityManager->getRepository(User::class)->find($id);
        if (!$user) {
            return new Response('User not found', Response::HTTP_NOT_FOUND);
        }

        $this->authorizeAdmin();

        $this->entityManager->remove($user);
        $this->entityManager->flush();

        return new Response('User deleted', Response::HTTP_OK);
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
