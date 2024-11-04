<?php

namespace App\Controller;

use App\Entity\User;
use Doctrine\ORM\EntityManagerInterface;
use Lexik\Bundle\JWTAuthenticationBundle\Services\JWTTokenManagerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Security\Http\Attribute\CurrentUser;


class AuthenticationController extends AbstractController
{
   private EntityManagerInterface $em;

   public function __construct(EntityManagerInterface $em)
   {
      $this->em = $em;
   }

   #[Route('api/register', name: 'register', methods: 'post')]
   public function register(UserPasswordHasherInterface $passwordHasher, JWTTokenManagerInterface $JWTManager): Response
   {
      $request = Request::createFromGlobals();
      $data = json_decode($request->getContent(), true);
      $email = $data['email'] ?? null; // Use null coalescing operator to handle missing values
      $password = $data['password'] ?? null;      // check if the user exists 

      $user = $this->em->getRepository(User::class)->findOneBy(['email' => $email]);

      if ($user) {
         return new Response("User already registered under $email", Response::HTTP_CONFLICT);
      }

      // store the user in the database
      $newUser = new User();
      $newUser->setEmail($email);
      $hashedPassword = $passwordHasher->hashPassword(
         $newUser,
         $password
      );

      $newUser->setPassword($hashedPassword);
      $this->em->persist($newUser);
      //Save the user to the database
      $this->em->flush();

      // return an auth token to the user
      $token = $JWTManager->create($newUser);

      return new JsonResponse([
         'user' => $newUser->getUserIdentifier(),
         'token' => $token
      ], Response::HTTP_OK);
   }

   #[Route('/api/login', name: 'login', methods: ['POST'])]
   public function login(#[CurrentUser] ?User $user, UserPasswordHasherInterface $passwordHasher, JWTTokenManagerInterface $JWTManager): Response
   {
      if (null === $user) {
         return $this->json([
            'message' => 'missing credentials',
         ], Response::HTTP_UNAUTHORIZED);
      }

      $token = $JWTManager->create($user);

      return new JsonResponse([
         'user' => $user->getUserIdentifier(),
         'token' => $token
      ], Response::HTTP_OK);
   }

   #[Route('/api/test', name: 'test', methods: ['GET'])]
   public function test(): Response
   {
      return new JsonResponse([
         'welcome-msg' => 'Welcome to Rescue Rover'
      ], Response::HTTP_OK);
   }
}
