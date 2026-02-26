<?php

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Security\Http\Attribute\IsGranted;

#[Route('/api/users')]
class UserController extends AbstractController
{
    #[Route('/', methods: ['GET'])]
    public function index()
    {
        return $this->json([]);
    }

    #[Route('/', methods: ['POST'])]
    #[IsGranted('ROLE_ADMIN')]
    public function create()
    {
        // Create user
    }

    #[Route('/{id}', methods: ['PUT'])]
    #[IsGranted('ROLE_ADMIN')]
    public function update(int $id)
    {
        // Update user
    }

    #[Route('/{id}', methods: ['DELETE'])]
    #[IsGranted('ROLE_SUPER_ADMIN')]
    public function delete(int $id)
    {
        // Delete user
    }
}
